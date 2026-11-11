# keyhaven

**A local, encrypted password manager for the command line.** Your passwords stay in one
file on your own computer. They are encrypted with AES-256-GCM under a key stretched from your
master password with scrypt, and there's no account, no server and no tracking.

```console
$ keyhaven init
creating a vault at ~/.local/share/keyhaven/vault.json
new master password:
repeat the master password:

$ keyhaven add GitHub -u ada --url https://github.com --generate
master password:
generated a password (130 bits, excellent)
added 'GitHub'

$ keyhaven copy github
master password:
copied the password; the clipboard will be cleared in 20 s

$ keyhaven audit
master password:
used in more than one entry (2):
  Bank: same password as Mail
  Mail: same password as Bank
weak (1):
  Forum: very weak: this is one of the most common passwords
```

## Features

- **Encrypted vault.** It uses scrypt (128 MiB per guess) and AES-256-GCM, and the header is
  authenticated, so tampering is detected. Saves are atomic, a backup file is kept, and a lock
  stops two processes from overwriting each other. See [the security design](docs/security.md).
- **Entries** have usernames, URLs, notes, tags, custom fields and favorites. Each one keeps a
  history of its earlier passwords. Entries can be found by title, part of a title or id, with
  "did you mean…?" suggestions.
- **Generator.** Make random passwords, pronounceable passphrases (`kodate-mivuno-…`) or PINs.
  Each reports its exact entropy.
- **Strength checks** look for what attackers actually try, such as common passwords, l33t
  speak, keyboard runs, years and your own name. The feedback is in plain words.
- **Two-factor codes (TOTP)** come from a site's secret or its `otpauth://` QR link, and are
  checked against the RFC test vectors.
- **Clipboard copy** clears itself after 20 seconds, but only if the clipboard still holds what
  keyhaven put there.
- **Audit** finds weak, reused, near-identical and old passwords. `--online` also checks
  known breaches (Have I Been Pwned, k-anonymous: only 5 hash characters are sent).
- **Import** from Bitwarden, Chrome/Edge/Brave, Firefox and 1Password CSV exports. You can also
  export, or make encrypted backups.

## Install

keyhaven needs Python 3.11 or newer.

```console
$ pipx install git+https://github.com/zeexduaa/keyhaven      # or: pip install --user ...
```

The clipboard uses your system's tool: `pbcopy` on macOS, PowerShell on Windows, and
`wl-clipboard` (Wayland) or `xclip`/`xsel` (X11) on Linux.

## Commands

| command | what it does |
|---|---|
| `init` | create a vault (`--scrypt-log-n` sets the key-stretching cost) |
| `add TITLE` | add an entry: `-u USER`, `--url`, `--tags a,b`, `--notes`, `--totp SECRET`, `--field k=v`, `--generate` |
| `list [QUERY]`, `search QUERY` | list or search entries; `-t TAG` filters by tag |
| `show ENTRY` | show an entry and its current 2FA code; `--reveal` shows the password |
| `copy ENTRY [FIELD]` | copy the password, or `username`, `url`, `totp` or a custom field |
| `edit ENTRY` | change fields; `--generate` or `--password` sets a new password (the old one goes to history) |
| `rm ENTRY` | delete an entry |
| `history ENTRY` | earlier passwords of an entry |
| `totp ENTRY` | the current two-factor code |
| `generate` | passwords (`--length`, `--no-symbols`, `--no-ambiguous`), passphrases (`--words N`) or PINs (`--pin N`) |
| `check` | how strong is a password? (nothing is stored) |
| `audit` | find weak, reused, similar and old passwords; `--online` checks breaches |
| `import FILE` | import a CSV or JSON export (`--dry-run` to preview) |
| `export FILE` | export to plain-text CSV or JSON (asks first) |
| `backup PATH` | copy the encrypted vault to a file or folder |
| `passwd` | change the master password |
| `info` | the vault's location and protection (no password needed) |
| `set [NAME VALUE]` | settings: `clipboard_seconds`, `history_limit` |

The vault is `~/.local/share/keyhaven/vault.json` on Linux,
`~/Library/Application Support/keyhaven/` on macOS, and `%APPDATA%\keyhaven\` on Windows.
Use `--vault PATH` or `KEYHAVEN_VAULT` to choose another file.

## Use it as a library

```python
from keyhaven.vault import Vault
from keyhaven.entries import Entries, Entry
from keyhaven import generator, totp

entries = Entries(Vault.open("vault.json", master_password))
entries.add(Entry(title="Example", username="ada", password=generator.password(24).value))
entries.save()
```

## Status

keyhaven is young. The core is complete and tested on Linux, macOS and Windows. It has not had
an independent security review yet, so read [what it does not protect against](docs/security.md#what-it-does-not-protect-against)
before you trust it with everything. The [roadmap](ROADMAP.md) lists what's planned: a
session agent so you unlock once, sync, hardware keys, a browser extension and more.

## Development

```console
$ pip install -e . pytest
$ pytest
```

The tests use cheap scrypt settings, so the whole suite runs in about a second.

## License

MIT
