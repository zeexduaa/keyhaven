import base64
import json
import os

import pytest

from keyhaven import crypto
from keyhaven.crypto import CryptoError, DecryptError, KdfParams
from keyhaven.vault import Vault, VaultCorrupt, VaultError, VaultLock, VaultLocked, WrongPassword


# -- crypto --------------------------------------------------------------------------------------


def test_encrypt_round_trip_and_fresh_nonces():
    key = crypto.new_key()
    n1, c1 = crypto.encrypt(key, b"secret", b"aad")
    n2, c2 = crypto.encrypt(key, b"secret", b"aad")
    assert n1 != n2 and c1 != c2                # same message, different ciphertext
    assert crypto.decrypt(key, n1, c1, b"aad") == b"secret"


@pytest.mark.parametrize("change", ["key", "nonce", "ciphertext", "aad"])
def test_any_change_fails_decryption(change):
    key = crypto.new_key()
    nonce, ct = crypto.encrypt(key, b"secret", b"aad")
    args = {"key": key, "nonce": nonce, "ciphertext": ct, "aad": b"aad"}
    value = bytearray(args[change])
    value[0] ^= 1
    args[change] = bytes(value)
    with pytest.raises(DecryptError):
        crypto.decrypt(args["key"], args["nonce"], args["ciphertext"], args["aad"])


def test_kdf_is_deterministic_and_salted(fast_kdf):
    params = fast_kdf()
    assert crypto.derive_key("pw", params) == crypto.derive_key("pw", params)
    assert crypto.derive_key("pw", params) != crypto.derive_key("pw", fast_kdf())     # another salt
    assert crypto.derive_key("pw", params) != crypto.derive_key("pW", params)


def test_unicode_passwords_are_normalized(fast_kdf):
    params = fast_kdf()
    composed, decomposed = "café", "café"
    assert composed != decomposed
    assert crypto.derive_key(composed, params) == crypto.derive_key(decomposed, params)


@pytest.mark.parametrize("n, r, p, message", [
    (1000, 8, 1, "power of two"), (2 ** 30, 8, 1, "power of two"), (2 ** 20, 32, 1, "1 GiB"),
    (2 ** 14, 0, 1, "r must be"), (2 ** 14, 8, 99, "p must be"),
])
def test_unsafe_kdf_settings_are_rejected(n, r, p, message):
    with pytest.raises(CryptoError, match=message):
        KdfParams(n, r, p, b"s" * 16).validate()


def test_default_kdf_settings_are_strong():
    params = KdfParams.new()
    assert params.n >= 2 ** 17 and params.r >= 8 and params.memory >= 128 * 1024 * 1024


# -- vault files ---------------------------------------------------------------------------------


def test_create_save_and_open(tmp_path, fast_kdf):
    path = tmp_path / "vault.json"
    vault = Vault.create(path, "correct horse", fast_kdf())
    vault.payload["entries"].append({"title": "mail", "password": "hunter2"})
    vault.save()
    reopened = Vault.open(path, "correct horse")
    assert reopened.payload["entries"] == [{"title": "mail", "password": "hunter2"}]
    text = path.read_text()
    assert "hunter2" not in text and "mail" not in text       # nothing readable on disk
    if os.name == "posix":
        assert oct(path.stat().st_mode & 0o777) == "0o600"


def test_wrong_password(tmp_path, fast_kdf):
    path = tmp_path / "vault.json"
    Vault.create(path, "right", fast_kdf())
    with pytest.raises(WrongPassword):
        Vault.open(path, "wrong")


def test_create_refuses_to_overwrite(tmp_path, fast_kdf):
    path = tmp_path / "vault.json"
    Vault.create(path, "pw", fast_kdf())
    with pytest.raises(VaultError, match="already exists"):
        Vault.create(path, "pw", fast_kdf())
    with pytest.raises(VaultError, match="can't be empty"):
        Vault.create(tmp_path / "other.json", "", fast_kdf())


def tamper(path, edit):
    doc = json.loads(path.read_text())
    edit(doc)
    path.write_text(json.dumps(doc))


def test_tampered_header_is_rejected(tmp_path, fast_kdf):
    path = tmp_path / "vault.json"
    Vault.create(path, "pw", fast_kdf())
    # Weakening the scrypt cost (or any header change) must not be accepted silently.
    tamper(path, lambda d: d["kdf"].update(n=d["kdf"]["n"] * 2))
    with pytest.raises(WrongPassword):
        Vault.open(path, "pw")


def test_tampered_entries_are_reported_as_damage_not_a_wrong_password(tmp_path, fast_kdf):
    path = tmp_path / "vault.json"
    Vault.create(path, "pw", fast_kdf())

    def flip(d):
        raw = bytearray(base64.b64decode(d["data"]["ciphertext"]))
        raw[-1] ^= 1
        d["data"]["ciphertext"] = base64.b64encode(bytes(raw)).decode()
    tamper(path, flip)
    with pytest.raises(VaultCorrupt, match="master password is right"):
        Vault.open(path, "pw")


def test_key_and_data_ciphertexts_cant_be_swapped(tmp_path, fast_kdf):
    path = tmp_path / "vault.json"
    Vault.create(path, "pw", fast_kdf())
    tamper(path, lambda d: d.update(key=d["data"], data=d["key"]))
    with pytest.raises(WrongPassword):
        Vault.open(path, "pw")


@pytest.mark.parametrize("content, message", [
    (b"not json", "isn't valid JSON"),
    (b'{"format": "other"}', "isn't a keyhaven vault"),
    (b'{"format": "keyhaven", "version": 99, "cipher": "aes-256-gcm", "key": {}, "data": {}}', "newer keyhaven"),
])
def test_files_that_arent_vaults(tmp_path, content, message):
    path = tmp_path / "vault.json"
    path.write_bytes(content)
    with pytest.raises(VaultError, match=message):
        Vault.open(path, "pw")


def test_a_hostile_header_cant_exhaust_memory(tmp_path, fast_kdf):
    path = tmp_path / "vault.json"
    Vault.create(path, "pw", fast_kdf())
    tamper(path, lambda d: d["kdf"].update(n=2 ** 22, r=32))
    with pytest.raises(VaultCorrupt, match="1 GiB"):
        Vault.open(path, "pw")


def test_missing_vault(tmp_path):
    with pytest.raises(VaultError, match="keyhaven init"):
        Vault.open(tmp_path / "nope.json", "pw")


def test_change_password_keeps_entries_and_uses_a_new_salt(tmp_path, fast_kdf):
    path = tmp_path / "vault.json"
    vault = Vault.create(path, "old", fast_kdf())
    vault.payload["entries"].append({"title": "x"})
    vault.save()
    old_salt = vault.kdf.salt
    vault.change_password("new")
    assert vault.kdf.salt != old_salt
    with pytest.raises(WrongPassword):
        Vault.open(path, "old")
    assert Vault.open(path, "new").payload["entries"] == [{"title": "x"}]
    assert vault.verify_password("new") and not vault.verify_password("old")


def test_saving_keeps_the_previous_version_as_a_backup(tmp_path, fast_kdf):
    path = tmp_path / "vault.json"
    vault = Vault.create(path, "pw", fast_kdf())
    vault.payload["entries"].append({"title": "first"})
    vault.save()
    vault.payload["entries"].append({"title": "second"})
    vault.save()
    backup = tmp_path / "vault.json.bak"
    assert [e["title"] for e in Vault.open(backup, "pw").payload["entries"]] == ["first"]
    assert not [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]


# -- locking ---------------------------------------------------------------------------------------


def test_lock_excludes_a_second_writer(tmp_path):
    path = tmp_path / "vault.json"
    with VaultLock(path):
        with pytest.raises(VaultLocked, match="being changed by another keyhaven"):
            with VaultLock(path):
                pass
    with VaultLock(path):            # released
        pass
    assert not (tmp_path / "vault.json.lock").exists()


def test_a_lock_left_by_a_dead_process_is_taken_over(tmp_path):
    import socket
    lock = tmp_path / "vault.json.lock"
    lock.write_text(json.dumps({"pid": 2 ** 22 + 12345, "host": socket.gethostname()}))
    with VaultLock(tmp_path / "vault.json"):
        assert json.loads(lock.read_text())["pid"] == os.getpid()


def test_a_lock_from_another_machine_is_respected(tmp_path):
    lock = tmp_path / "vault.json.lock"
    lock.write_text(json.dumps({"pid": 1, "host": "some-other-machine"}))
    with pytest.raises(VaultLocked, match="some-other-machine"):
        with VaultLock(tmp_path / "vault.json"):
            pass
