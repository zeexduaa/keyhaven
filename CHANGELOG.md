# Changelog

## Unreleased (0.1.0)

First version.

- Encrypted vault: scrypt key stretching, AES-256-GCM with a separate data key, an
  authenticated header, atomic saves with a backup file, and locking.
- Entries: tags, custom fields, favorites, password history, and search with "did you mean".
- Generator for passwords, pronounceable passphrases and PINs, with exact entropy.
- Password strength estimates with plain-language warnings and suggestions.
- Two-factor codes (HOTP/TOTP, RFC 4226 and 6238) from base32 secrets or otpauth:// links.
- Command line: init, add, list, search, show, copy, edit, rm, history, generate, check, totp,
  audit, import, export, backup, tags, passwd, info and set.
- Clipboard copy that clears itself, on macOS, Windows, Wayland and X11.
- Audit for weak, reused, similar and old passwords, with an optional k-anonymous breach check.
- Import from Bitwarden, Chromium browsers, Firefox and 1Password.
