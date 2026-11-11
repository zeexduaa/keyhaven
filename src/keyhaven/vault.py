"""The vault file: format, opening, saving.

A vault is a small JSON file:

    {
      "format": "keyhaven", "version": 1,
      "kdf": {"name": "scrypt", "n": 131072, "r": 8, "p": 1, "salt": "..."},
      "cipher": "aes-256-gcm",
      "key":  {"nonce": "...", "ciphertext": "..."},     the data key, encrypted
      "data": {"nonce": "...", "ciphertext": "..."}      the entries, encrypted
    }

Two keys:

1. scrypt(master password, salt) gives the *key-encryption key*. It only ever
   encrypts the data key.
2. The *data key* is 32 random bytes made when the vault is created. It
   encrypts the entries.

So changing the master password re-encrypts 32 bytes, not the whole vault, and
a weak spot in one place doesn't expose the other. The header (format, version,
kdf, cipher) is the associated data of both encryptions: changing anything in it
(say, to weaken the scrypt cost) makes opening fail instead of being trusted.

Saving is atomic (write a temp file, flush it to disk, rename over the old one),
the previous version is kept as ``<vault>.bak``, and a lock file stops two
keyhaven processes from writing the same vault at once.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import crypto
from .crypto import CryptoError, DecryptError, KdfParams

FORMAT = "keyhaven"
VERSION = 1
CIPHER = "aes-256-gcm"


class VaultError(Exception):
    pass


class WrongPassword(VaultError):
    def __init__(self) -> None:
        super().__init__("wrong master password (or the vault file was changed)")


class VaultCorrupt(VaultError):
    pass


class VaultLocked(VaultError):
    pass


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(text: Any, what: str) -> bytes:
    if not isinstance(text, str):
        raise VaultCorrupt(f"the vault file is damaged: {what} is missing")
    try:
        return base64.b64decode(text, validate=True)
    except ValueError:
        raise VaultCorrupt(f"the vault file is damaged: {what} isn't valid base64") from None


def header_bytes(header: dict[str, Any], purpose: str) -> bytes:
    """The associated data: the header in a canonical form, plus what this ciphertext is for
    (so the encrypted key and the encrypted data can't be swapped)."""
    canonical = json.dumps(header, sort_keys=True, separators=(",", ":"))
    return f"{canonical}|{purpose}".encode("utf-8")


def empty_payload() -> dict[str, Any]:
    stamp = now()
    return {"entries": [], "created": stamp, "modified": stamp,
            "settings": {"clipboard_seconds": 20, "history_limit": 10}}


@dataclass
class Vault:
    path: Path
    payload: dict[str, Any]
    kdf: KdfParams
    _data_key: bytes = field(repr=False)
    _wrapped_key: tuple[bytes, bytes] = field(repr=False)

    # -- creating and opening ------------------------------------------------------------------------

    @classmethod
    def create(cls, path: str | Path, password: str, kdf: KdfParams | None = None,
               overwrite: bool = False) -> Vault:
        path = Path(path)
        if path.exists() and not overwrite:
            raise VaultError(f"{path} already exists")
        if not password:
            raise VaultError("the master password can't be empty")
        kdf = kdf or KdfParams.new()
        data_key = crypto.new_key()
        vault = cls(path, empty_payload(), kdf, data_key, (b"", b""))
        vault._wrap_key(password)
        vault.save()
        return vault

    @classmethod
    def open(cls, path: str | Path, password: str) -> Vault:
        path = Path(path)
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            raise VaultError(f"no vault at {path}; create one with: keyhaven init") from None
        doc = parse_document(raw)
        header = doc_header(doc)
        kdf = kdf_from_header(header)
        try:
            kek = crypto.derive_key(password, kdf)
        except CryptoError as exc:
            raise VaultCorrupt(f"the vault's key settings are invalid: {exc}") from None
        key_nonce, key_ct = unb64(doc["key"].get("nonce"), "key nonce"), unb64(doc["key"].get("ciphertext"), "key")
        try:
            data_key = crypto.decrypt(kek, key_nonce, key_ct, header_bytes(header, "key"))
        except DecryptError:
            raise WrongPassword() from None
        data_nonce = unb64(doc["data"].get("nonce"), "data nonce")
        data_ct = unb64(doc["data"].get("ciphertext"), "data")
        try:
            plaintext = crypto.decrypt(data_key, data_nonce, data_ct, header_bytes(header, "data"))
        except DecryptError:
            # The password was right (the data key decrypted), so the entries were changed or damaged.
            raise VaultCorrupt("the vault's entries were changed or damaged (the master password is right); "
                               f"try the backup: {path}.bak") from None
        try:
            payload = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise VaultCorrupt("the vault decrypted but its contents aren't valid") from None
        if not isinstance(payload, dict) or not isinstance(payload.get("entries"), list):
            raise VaultCorrupt("the vault decrypted but its contents aren't valid")
        payload.setdefault("settings", {}).setdefault("clipboard_seconds", 20)
        payload["settings"].setdefault("history_limit", 10)
        return cls(path, payload, kdf, data_key, (key_nonce, key_ct))

    # -- keys ------------------------------------------------------------------------------------------

    def header(self) -> dict[str, Any]:
        return {"format": FORMAT, "version": VERSION,
                "kdf": {"name": "scrypt", "n": self.kdf.n, "r": self.kdf.r, "p": self.kdf.p, "salt": b64(self.kdf.salt)},
                "cipher": CIPHER}

    def _wrap_key(self, password: str) -> None:
        kek = crypto.derive_key(password, self.kdf)
        self._wrapped_key = crypto.encrypt(kek, self._data_key, header_bytes(self.header(), "key"))

    def change_password(self, new_password: str, kdf: KdfParams | None = None) -> None:
        """Re-encrypts the data key under a new master password (and a new salt). The entries
        keep their data key, so this is quick and can't damage them."""
        if not new_password:
            raise VaultError("the master password can't be empty")
        self.kdf = kdf or KdfParams.new(self.kdf.n, self.kdf.r, self.kdf.p)
        self._wrap_key(new_password)
        self.save()

    def verify_password(self, password: str) -> bool:
        try:
            kek = crypto.derive_key(password, self.kdf)
            nonce, ct = self._wrapped_key
            return crypto.decrypt(kek, nonce, ct, header_bytes(self.header(), "key")) == self._data_key
        except DecryptError:
            return False

    # -- saving --------------------------------------------------------------------------------------------

    def to_bytes(self) -> bytes:
        header = self.header()
        self.payload["modified"] = now()
        plaintext = json.dumps(self.payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        data_nonce, data_ct = crypto.encrypt(self._data_key, plaintext, header_bytes(header, "data"))
        key_nonce, key_ct = self._wrapped_key
        doc = dict(header)
        doc["key"] = {"nonce": b64(key_nonce), "ciphertext": b64(key_ct)}
        doc["data"] = {"nonce": b64(data_nonce), "ciphertext": b64(data_ct)}
        return (json.dumps(doc, indent=2) + "\n").encode("utf-8")

    def save(self) -> None:
        atomic_write(self.path, self.to_bytes(), keep_backup=True)


# -- reading the document -----------------------------------------------------------------------------------


def parse_document(raw: bytes) -> dict[str, Any]:
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise VaultCorrupt("this isn't a keyhaven vault (it isn't valid JSON)") from None
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise VaultCorrupt("this isn't a keyhaven vault")
    version = doc.get("version")
    if not isinstance(version, int):
        raise VaultCorrupt("the vault file is damaged: no version")
    if version > VERSION:
        raise VaultError(f"this vault was made by a newer keyhaven (format version {version}); please upgrade")
    if doc.get("cipher") != CIPHER:
        raise VaultCorrupt(f"unsupported cipher {doc.get('cipher')!r}")
    for part in ("key", "data"):
        if not isinstance(doc.get(part), dict):
            raise VaultCorrupt(f"the vault file is damaged: '{part}' is missing")
    return doc


def doc_header(doc: dict[str, Any]) -> dict[str, Any]:
    return {k: doc[k] for k in ("format", "version", "kdf", "cipher") if k in doc}


def kdf_from_header(header: dict[str, Any]) -> KdfParams:
    kdf = header.get("kdf")
    if not isinstance(kdf, dict) or kdf.get("name") != "scrypt":
        raise VaultCorrupt("the vault's key settings are missing or unsupported")
    try:
        params = KdfParams(int(kdf["n"]), int(kdf["r"]), int(kdf["p"]), unb64(kdf["salt"], "salt"))
    except (KeyError, TypeError, ValueError):
        raise VaultCorrupt("the vault's key settings are damaged") from None
    try:
        params.validate()
    except CryptoError as exc:
        raise VaultCorrupt(f"the vault's key settings are invalid: {exc}") from None
    return params


# -- files ---------------------------------------------------------------------------------------------------------


def atomic_write(path: Path, data: bytes, keep_backup: bool = False) -> None:
    """Writes ``data`` so that ``path`` always holds either the old or the new contents, never half.
    The file is readable only by its owner (0600) on systems that have permissions."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        try:
            os.chmod(tmp, 0o600)
        except OSError:  # pragma: no cover - e.g. some network filesystems
            pass
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if keep_backup and path.exists():
            backup = path.with_name(path.name + ".bak")
            atomic_copy(path, backup)
        os.replace(tmp, path)
        _fsync_dir(path.parent)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def atomic_copy(src: Path, dst: Path) -> None:
    data = src.read_bytes()
    fd, tmp = tempfile.mkstemp(prefix=f".{dst.name}.", suffix=".tmp", dir=dst.parent)
    try:
        try:
            os.chmod(tmp, 0o600)
        except OSError:  # pragma: no cover
            pass
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, dst)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _fsync_dir(directory: Path) -> None:
    if os.name != "posix":
        return
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:  # pragma: no cover
        return
    try:
        os.fsync(fd)
    except OSError:  # pragma: no cover
        pass
    finally:
        os.close(fd)


class VaultLock:
    """``with VaultLock(path):`` stops two keyhaven processes from changing a vault at once.

    The lock is a file next to the vault, created exclusively, holding the owner's pid and
    host. A lock left behind by a process that no longer exists (on this machine) is taken
    over; anything else is reported, with the path, so it can be removed by hand."""

    def __init__(self, vault_path: str | Path, wait: float = 0.0):
        self.path = Path(str(vault_path) + ".lock")
        self.wait = wait
        self.held = False

    def __enter__(self) -> VaultLock:
        deadline = time.monotonic() + self.wait
        while True:
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                if self._stale():
                    try:
                        os.unlink(self.path)
                    except FileNotFoundError:
                        pass
                    continue
                if time.monotonic() >= deadline:
                    owner = self._owner()
                    raise VaultLocked(f"the vault is being changed by another keyhaven ({owner}); if that's not "
                                      f"true, delete {self.path}") from None
                time.sleep(0.05)
                continue
            with os.fdopen(fd, "w") as f:
                f.write(json.dumps({"pid": os.getpid(), "host": socket.gethostname(), "since": now()}))
            self.held = True
            return self

    def __exit__(self, *exc: Any) -> None:
        if self.held:
            try:
                os.unlink(self.path)
            except FileNotFoundError:
                pass
            self.held = False

    def _info(self) -> dict[str, Any]:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _owner(self) -> str:
        info = self._info()
        return f"process {info.get('pid', '?')} on {info.get('host', '?')}"

    def _stale(self) -> bool:
        info = self._info()
        if not info:
            # Unreadable: maybe it's being written right now. Only call it stale once it's old.
            try:
                return time.time() - self.path.stat().st_mtime > 10
            except OSError:
                return False
        if info.get("host") != socket.gethostname() or not isinstance(info.get("pid"), int):
            return False
        return not _pid_alive(info["pid"])


def _pid_alive(pid: int) -> bool:
    if pid == os.getpid():
        return True
    if os.name == "nt":  # pragma: no cover - checked on Windows CI
        import ctypes
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(0x1000, False, pid)   # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        exit_code = ctypes.c_ulong()
        kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
        kernel32.CloseHandle(handle)
        return exit_code.value == 259                      # STILL_ACTIVE
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True
