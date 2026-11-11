"""The keyhaven command line.

    keyhaven init                         create a vault
    keyhaven add github --generate        add an entry with a new random password
    keyhaven copy github                  copy its password (cleared after 20 s)
    keyhaven show github                  see it (password hidden unless --reveal)
    keyhaven totp github                  the current two-factor code

The vault is found from --vault, then $KEYHAVEN_VAULT, then the platform's data
folder (``~/.local/share/keyhaven/vault.json`` on Linux). The master password is
always asked for on the terminal; it is never read from an argument or a
variable, where it would end up in shell history or process listings.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from . import __version__, clipboard, generator, strength, totp
from .crypto import CryptoError, KdfParams
from .entries import Entries, Entry, EntryError
from .vault import Vault, VaultError, VaultLock, WrongPassword, doc_header, kdf_from_header, parse_document

ask_secret = getpass.getpass        # replaced in tests
ask = input


class CliError(Exception):
    pass


# -- where the vault is ------------------------------------------------------------------------------------

def default_vault_path() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "keyhaven" / "vault.json"


def vault_path(args: argparse.Namespace) -> Path:
    if args.vault:
        return Path(args.vault).expanduser()
    if os.environ.get("KEYHAVEN_VAULT"):
        return Path(os.environ["KEYHAVEN_VAULT"]).expanduser()
    return default_vault_path()


# -- asking ---------------------------------------------------------------------------------------------------

def new_secret(prompt: str, what: str = "password", check_strength: bool = True,
               user_inputs: list[str] | None = None) -> str:
    """Asks twice; warns (and asks to confirm) if the password is weak."""
    for _ in range(3):
        first = ask_secret(f"{prompt}: ")
        if not first:
            print(f"the {what} can't be empty", file=sys.stderr)
            continue
        if ask_secret(f"repeat the {what}: ") != first:
            print(f"the two {what}s don't match; try again", file=sys.stderr)
            continue
        if check_strength:
            result = strength.estimate(first, user_inputs)
            if result.score < 3:
                print(f"that {what} is {result.label} (time to crack: {result.crack_time})", file=sys.stderr)
                for line in result.warnings + result.suggestions:
                    print(f"  - {line}", file=sys.stderr)
                if not confirm("use it anyway?"):
                    continue
        return first
    raise CliError(f"no {what} given")


def confirm(question: str) -> bool:
    try:
        return ask(f"{question} [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


@contextmanager
def opened(args: argparse.Namespace, write: bool = False) -> Iterator[Entries]:
    """Opens the vault (asking for the master password). With write=True the vault is locked
    for the whole command, so two keyhaven processes can't overwrite each other's changes."""
    path = vault_path(args)
    lock = VaultLock(path) if write else None
    if lock:
        lock.__enter__()
    try:
        if not path.exists():
            raise CliError(f"no vault at {path}; create one with: keyhaven init")
        for attempt in range(3):
            try:
                vault = Vault.open(path, ask_secret("master password: "))
                break
            except WrongPassword:
                if attempt == 2:
                    raise
                print("wrong master password; try again", file=sys.stderr)
        yield Entries(vault)
    finally:
        if lock:
            lock.__exit__(None, None, None)


# -- printing --------------------------------------------------------------------------------------------------

def table(rows: list[list[str]], headers: list[str]) -> str:
    widths = [min(max(len(str(r[i])) for r in rows + [headers]), 40) for i in range(len(headers))]

    def line(cells: list[str]) -> str:
        return "  ".join(str(c)[:w].ljust(w) for c, w in zip(cells, widths)).rstrip()
    return "\n".join([line(headers), line(["-" * w for w in widths])] + [line(r) for r in rows])


def show_entry(entry: Entry, reveal: bool) -> str:
    lines = [f"{entry.title}{'  *' if entry.favorite else ''}   (id {entry.id[:8]})"]
    for label, value in (("username", entry.username), ("url", entry.url)):
        if value:
            lines.append(f"  {label + ':':<11}{value}")
    if entry.password:
        lines.append(f"  {'password:':<11}{entry.password if reveal else '•' * 10 + '  (--reveal to show)'}")
    if entry.totp:
        try:
            config = totp.parse(entry.totp)
            lines.append(f"  {'2fa code:':<11}{totp.code(config)}  ({totp.seconds_left(config)} s left)")
        except totp.TotpError as exc:
            lines.append(f"  {'2fa code:':<11}(the stored secret is invalid: {exc})")
    for name, value in entry.fields.items():
        lines.append(f"  {name + ':':<11}{value}")
    if entry.tags:
        lines.append(f"  {'tags:':<11}{', '.join(entry.tags)}")
    if entry.notes:
        lines.append("  notes:")
        lines.extend(f"    {line}" for line in entry.notes.splitlines())
    lines.append(f"  {'changed:':<11}{entry.modified[:10]}  (password set {entry.password_changed[:10]}"
                 f"{', ' + str(len(entry.history)) + ' older' if entry.history else ''})")
    return "\n".join(lines)


def generated_from(args: argparse.Namespace) -> generator.Generated:
    if getattr(args, "words", None):
        return generator.passphrase(args.words, separator=args.separator, capitalize=args.capitalize,
                                    with_number=args.with_number)
    if getattr(args, "pin", None):
        return generator.pin(args.pin)
    return generator.password(args.length, symbols=not args.no_symbols, avoid_ambiguous=args.no_ambiguous)


def parse_fields(pairs: list[str] | None) -> dict[str, str]:
    fields = {}
    for pair in pairs or []:
        name, sep, value = pair.partition("=")
        if not sep or not name.strip():
            raise CliError(f"--field needs NAME=VALUE, not '{pair}'")
        fields[name.strip()] = value
    return fields


def check_totp(secret: str | None) -> str | None:
    if secret:
        totp.parse(secret)          # refuse to store a secret that can't make codes
    return secret


# -- commands -------------------------------------------------------------------------------------------------------

def cmd_init(args: argparse.Namespace) -> int:
    path = vault_path(args)
    if path.exists() and not args.force:
        raise CliError(f"there's already a vault at {path} (use --force to replace it, which destroys it)")
    print(f"creating a vault at {path}")
    print("choose a master password you can remember: it can't be recovered if you forget it.")
    password = new_secret("new master password", "master password")
    kdf = KdfParams.new(n=2 ** args.scrypt_log_n)
    path.parent.mkdir(parents=True, exist_ok=True)
    Vault.create(path, password, kdf, overwrite=args.force)
    print("done. add your first entry with: keyhaven add <title>")
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    with opened(args, write=True) as entries:
        if args.generate:
            made = generated_from(args)
            password = made.value
            print(f"generated a password ({made.entropy:.0f} bits, {generator.describe_entropy(made.entropy)})")
        elif args.no_password:
            password = ""
        else:
            password = new_secret("password for this entry", user_inputs=[args.title, args.username or "", args.url or ""])
        entry = entries.add(Entry(title=args.title, username=args.username or "", password=password,
                                  url=args.url or "", notes=args.notes or "", tags=args.tags or [],
                                  totp=check_totp(args.totp) or "", fields=parse_fields(args.field),
                                  favorite=args.favorite))
        entries.save()
        print(f"added '{entry.title}'")
        if args.copy and password:
            copy_secret(entries, password, "password")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    with opened(args) as entries:
        found = entries.search(args.query or "", args.tag)
        if not found:
            print("no entries" if not len(entries) else "nothing matches")
            return 0 if not args.query else 1
        rows = [[("* " if e.favorite else "") + e.title, e.username, e.url, ", ".join(e.tags)] for e in found]
        print(table(rows, ["title", "username", "url", "tags"]))
        print(f"\n{len(found)} of {len(entries)} entries")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    with opened(args) as entries:
        print(show_entry(entries.find(args.entry), args.reveal))
    return 0


def copy_secret(entries: Entries, value: str, what: str) -> None:
    seconds = int(entries.vault.payload["settings"].get("clipboard_seconds", 20))
    clipboard.copy_and_clear_later(value, seconds)
    print(f"copied the {what}" + (f"; the clipboard will be cleared in {seconds} s" if seconds else ""))


def cmd_copy(args: argparse.Namespace) -> int:
    with opened(args) as entries:
        entry = entries.find(args.entry)
        what = args.field
        if what == "password":
            value = entry.password
        elif what in ("username", "url", "notes"):
            value = getattr(entry, what)
        elif what in ("totp", "2fa", "code"):
            if not entry.totp:
                raise CliError(f"'{entry.title}' has no 2FA secret")
            value, what = totp.code(totp.parse(entry.totp)), "2FA code"
        elif what in entry.fields:
            value = entry.fields[what]
        else:
            raise CliError(f"'{entry.title}' has no field '{what}'")
        if not value:
            raise CliError(f"'{entry.title}' has no {what}")
        copy_secret(entries, value, what)
    return 0


def cmd_edit(args: argparse.Namespace) -> int:
    with opened(args, write=True) as entries:
        entry = entries.find(args.entry)
        changes: dict = {}
        for name in ("title", "username", "url", "notes"):
            if getattr(args, name) is not None:
                changes[name] = getattr(args, name)
        if args.tags is not None:
            changes["tags"] = args.tags
        if args.add_tag or args.remove_tag:
            tags = [t for t in changes.get("tags", entry.tags)
                    if t.lower() not in {r.lower() for r in args.remove_tag or []}]
            changes["tags"] = tags + (args.add_tag or [])
        if args.totp is not None:
            changes["totp"] = check_totp(args.totp)
        if args.field or args.remove_field:
            fields = dict(entry.fields)
            for name in args.remove_field or []:
                if fields.pop(name, None) is None:
                    raise CliError(f"'{entry.title}' has no field '{name}'")
            fields.update(parse_fields(args.field))
            changes["fields"] = fields
        if args.favorite is not None:
            changes["favorite"] = args.favorite
        if args.generate:
            made = generated_from(args)
            changes["password"] = made.value
            print(f"generated a new password ({made.entropy:.0f} bits); the old one is kept in the history")
        elif args.password:
            changes["password"] = new_secret("new password for this entry",
                                             user_inputs=[entry.title, entry.username, entry.url])
        if not changes:
            raise CliError("nothing to change; see keyhaven edit --help")
        entries.update(entry, **changes)
        entries.save()
        print(f"updated '{entry.title}'")
        if args.copy and "password" in changes:
            copy_secret(entries, entry.password, "password")
    return 0


def cmd_rm(args: argparse.Namespace) -> int:
    with opened(args, write=True) as entries:
        entry = entries.find(args.entry)
        if not args.yes and not confirm(f"delete '{entry.title}'? the backup file keeps the previous version until the next save"):
            print("kept it")
            return 1
        entries.remove(entry)
        entries.save()
        print(f"deleted '{entry.title}'")
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    with opened(args) as entries:
        entry = entries.find(args.entry)
        if not entry.history:
            print(f"'{entry.title}' has no earlier passwords")
            return 0
        print(f"earlier passwords of '{entry.title}' (newest first):")
        for item in entry.history:
            shown = item["password"] if args.reveal else "•" * 10
            print(f"  until {item['changed'][:10]}  {shown}")
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    made = generated_from(args)
    for _ in range(args.count):
        print(made.value)
        made = generated_from(args)
    print(f"{made.entropy:.0f} bits each ({generator.describe_entropy(made.entropy)})", file=sys.stderr)
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    password = ask_secret("password to check (not stored): ")
    result = strength.estimate(password)
    print(f"{result.label}: about {result.bits:.0f} bits; time to crack with a fast offline attack: {result.crack_time}")
    for line in result.warnings:
        print(f"  ! {line}")
    for line in result.suggestions:
        print(f"  - {line}")
    return 0 if result.score >= 3 else 1


def cmd_totp(args: argparse.Namespace) -> int:
    with opened(args) as entries:
        entry = entries.find(args.entry)
        if not entry.totp:
            raise CliError(f"'{entry.title}' has no 2FA secret; add one with: keyhaven edit '{entry.title}' --totp SECRET")
        config = totp.parse(entry.totp)
        print(f"{totp.code(config)}   ({totp.seconds_left(config)} s left)")
    return 0


def cmd_tags(args: argparse.Namespace) -> int:
    with opened(args) as entries:
        tags = entries.tags()
        if not tags:
            print("no tags yet")
        for tag, count in tags.items():
            print(f"{tag}  ({count})")
    return 0


def cmd_passwd(args: argparse.Namespace) -> int:
    with opened(args, write=True) as entries:
        password = new_secret("new master password", "master password")
        entries.vault.change_password(password)
        print("the master password is changed (the backup file still opens with the old one until the next save)")
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    """What can be seen without the master password: where, how big, how it is protected."""
    path = vault_path(args)
    if not path.exists():
        raise CliError(f"no vault at {path}; create one with: keyhaven init")
    header = doc_header(parse_document(path.read_bytes()))
    kdf = kdf_from_header(header)
    stat = path.stat()
    print(f"vault:      {path}")
    print(f"size:       {stat.st_size:,} bytes")
    print(f"format:     {header['format']} v{header['version']}, {header['cipher']}")
    print(f"key:        scrypt N=2^{kdf.n.bit_length() - 1}, r={kdf.r}, p={kdf.p} ({kdf.memory // 2**20} MiB per guess)")
    if os.name == "posix" and stat.st_mode & 0o077:
        print(f"warning:    other users can read this file; fix with: chmod 600 {path}")
    backup = path.with_name(path.name + ".bak")
    print(f"backup:     {backup if backup.exists() else '(none yet)'}")
    return 0


def cmd_set(args: argparse.Namespace) -> int:
    limits = {"clipboard_seconds": (0, 600), "history_limit": (0, 100)}
    with opened(args, write=True) as entries:
        settings = entries.vault.payload["settings"]
        if args.name is None:
            for name, value in settings.items():
                print(f"{name} = {value}")
            return 0
        if args.name not in limits:
            raise CliError(f"unknown setting '{args.name}' (settings: {', '.join(limits)})")
        try:
            value = int(args.value)
        except (TypeError, ValueError):
            raise CliError(f"{args.name} needs a whole number") from None
        low, high = limits[args.name]
        if not low <= value <= high:
            raise CliError(f"{args.name} must be between {low} and {high}")
        settings[args.name] = value
        entries.save()
        print(f"{args.name} = {value}")
    return 0


# -- the parser ------------------------------------------------------------------------------------------------------

def add_generator_options(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("generating")
    group.add_argument("--length", type=int, default=20, help="password length (default 20)")
    group.add_argument("--no-symbols", action="store_true", help="letters and digits only")
    group.add_argument("--no-ambiguous", action="store_true", help="avoid look-alikes such as l, 1, O and 0")
    group.add_argument("--words", type=int, metavar="N", help="a passphrase of N words instead")
    group.add_argument("--separator", default="-", help="between passphrase words (default -)")
    group.add_argument("--capitalize", action="store_true", help="capitalize passphrase words")
    group.add_argument("--with-number", action="store_true", help="add a digit to a passphrase")
    group.add_argument("--pin", type=int, metavar="N", help="an N-digit PIN instead")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="keyhaven", description="A local, encrypted password manager.")
    parser.add_argument("--version", action="version", version=f"keyhaven {__version__}")
    parser.add_argument("--vault", metavar="PATH", help="the vault file (default: $KEYHAVEN_VAULT or "
                        f"{default_vault_path()})")
    sub = parser.add_subparsers(dest="command", metavar="command")

    p = sub.add_parser("init", help="create a new vault")
    p.add_argument("--force", action="store_true", help="replace an existing vault (destroys it)")
    p.add_argument("--scrypt-log-n", type=int, default=17, metavar="K",
                   help="key stretching cost: scrypt N = 2^K (default 17, 128 MiB; higher is slower and safer)")
    p.set_defaults(run=cmd_init)

    p = sub.add_parser("add", help="add an entry")
    p.add_argument("title")
    p.add_argument("-u", "--username")
    p.add_argument("--url")
    p.add_argument("--notes")
    p.add_argument("--tags", type=lambda s: s.split(","), help="comma-separated")
    p.add_argument("--totp", metavar="SECRET", help="2FA secret (base32 or otpauth:// link)")
    p.add_argument("--field", action="append", metavar="NAME=VALUE", help="a custom field (repeatable)")
    p.add_argument("--favorite", action="store_true")
    p.add_argument("-g", "--generate", action="store_true", help="generate the password")
    p.add_argument("--no-password", action="store_true", help="an entry without a password")
    p.add_argument("-c", "--copy", action="store_true", help="copy the password afterwards")
    add_generator_options(p)
    p.set_defaults(run=cmd_add)

    for name, help_text in (("list", "list entries"), ("search", "search titles, usernames, URLs, tags and notes")):
        p = sub.add_parser(name, aliases=["ls"] if name == "list" else [], help=help_text)
        p.add_argument("query", nargs="?" if name == "list" else None)
        p.add_argument("-t", "--tag", help="only entries with this tag")
        p.set_defaults(run=cmd_list)

    p = sub.add_parser("show", help="show an entry")
    p.add_argument("entry", help="title, part of a title, or id")
    p.add_argument("-r", "--reveal", action="store_true", help="show the password")
    p.set_defaults(run=cmd_show)

    p = sub.add_parser("copy", aliases=["cp"], help="copy a password (or other field) to the clipboard")
    p.add_argument("entry")
    p.add_argument("field", nargs="?", default="password",
                   help="password (default), username, url, totp, or a custom field's name")
    p.set_defaults(run=cmd_copy)

    p = sub.add_parser("edit", help="change an entry")
    p.add_argument("entry")
    p.add_argument("--title")
    p.add_argument("-u", "--username")
    p.add_argument("--url")
    p.add_argument("--notes")
    p.add_argument("--tags", type=lambda s: s.split(","), help="replace the tags (comma-separated)")
    p.add_argument("--add-tag", action="append")
    p.add_argument("--remove-tag", action="append")
    p.add_argument("--totp", metavar="SECRET", help="set the 2FA secret ('' removes it)")
    p.add_argument("--field", action="append", metavar="NAME=VALUE")
    p.add_argument("--remove-field", action="append", metavar="NAME")
    fav = p.add_mutually_exclusive_group()
    fav.add_argument("--favorite", dest="favorite", action="store_true", default=None)
    fav.add_argument("--no-favorite", dest="favorite", action="store_false")
    pw = p.add_mutually_exclusive_group()
    pw.add_argument("-p", "--password", action="store_true", help="type a new password")
    pw.add_argument("-g", "--generate", action="store_true", help="generate a new password")
    p.add_argument("-c", "--copy", action="store_true", help="copy the new password")
    add_generator_options(p)
    p.set_defaults(run=cmd_edit)

    p = sub.add_parser("rm", aliases=["delete"], help="delete an entry")
    p.add_argument("entry")
    p.add_argument("-y", "--yes", action="store_true", help="don't ask")
    p.set_defaults(run=cmd_rm)

    p = sub.add_parser("history", help="an entry's earlier passwords")
    p.add_argument("entry")
    p.add_argument("-r", "--reveal", action="store_true")
    p.set_defaults(run=cmd_history)

    p = sub.add_parser("generate", aliases=["gen"], help="generate passwords without storing them")
    p.add_argument("-n", "--count", type=int, default=1)
    add_generator_options(p)
    p.set_defaults(run=cmd_generate)

    p = sub.add_parser("check", help="how strong is a password? (asks for it; nothing is stored)")
    p.set_defaults(run=cmd_check)

    p = sub.add_parser("totp", aliases=["2fa"], help="an entry's current two-factor code")
    p.add_argument("entry")
    p.set_defaults(run=cmd_totp)

    p = sub.add_parser("tags", help="list tags")
    p.set_defaults(run=cmd_tags)

    p = sub.add_parser("passwd", help="change the master password")
    p.set_defaults(run=cmd_passwd)

    p = sub.add_parser("info", help="about the vault file (no password needed)")
    p.set_defaults(run=cmd_info)

    p = sub.add_parser("set", help="show or change settings (clipboard_seconds, history_limit)")
    p.add_argument("name", nargs="?")
    p.add_argument("value", nargs="?")
    p.set_defaults(run=cmd_set)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "run", None):
        parser.print_help()
        return 0
    try:
        return args.run(args)
    except WrongPassword:
        print("keyhaven: wrong master password", file=sys.stderr)
        return 2
    except (CliError, VaultError, EntryError, CryptoError, totp.TotpError, generator.GeneratorError,
            clipboard.ClipboardError) as exc:
        print(f"keyhaven: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nkeyhaven: cancelled", file=sys.stderr)
        return 130
