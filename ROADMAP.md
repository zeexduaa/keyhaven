# Roadmap

keyhaven already works for daily use from the terminal: an encrypted vault, entries, a
generator, 2FA codes, the clipboard, an audit, and import/export. What follows is what's
left, roughly in order. Help with any of it is welcome.

## Next

- [ ] **Unlock once per session.** Today every command asks for the master password. Add an
      optional agent (like `ssh-agent`) that holds the data key in memory for a few minutes,
      reachable only through a socket that's private to the user.
- [ ] **Interactive mode.** `keyhaven shell`: unlock once and run commands, with tab completion
      of entry titles.
- [ ] **Rollback detection.** Remember (outside the vault) a counter of the last save and warn
      if an older vault appears.
- [ ] **Argon2id.** Offer it as an alternative to scrypt when `argon2-cffi` is installed. Store
      the choice in the header, as the format already allows.
- [ ] **More import formats.** KeePass XML and KDBX, LastPass, Dashlane, Proton Pass, and
      Bitwarden's JSON (with cards and identities).
- [ ] **Entry types.** Cards, identities, secure notes and SSH keys, each with its own fields
      and its own display.
- [ ] **Shell completion** for bash, zsh, fish and PowerShell.

## Later

- [ ] **Hardware keys.** A FIDO2/YubiKey second factor: the KEK is derived from both the master
      password and an `hmac-secret` from the key.
- [ ] **Sync between devices.** End-to-end encrypted. The data key never leaves the devices, and
      the server, whether a folder, WebDAV or S3, stores only the encrypted file. This needs
      a merge of concurrent changes, entry by entry, using the timestamps the format keeps.
- [ ] **A local web UI.** Served on localhost only, with a per-session token, for people who
      don't like terminals.
- [ ] **A browser extension** that fills logins, talking to the agent through native messaging.
- [ ] **Sharing.** Share an entry or a folder with another keyhaven user using public-key
      encryption (X25519).
- [ ] **Passkeys** (WebAuthn credentials) stored in the vault.
- [ ] **An independent security review** before a 1.0 release.

## Done

- [x] Vault format: scrypt, AES-256-GCM, authenticated header, separate data key.
- [x] Atomic saves, backup file and a lock against concurrent writes.
- [x] Entries with tags, custom fields, favorites and password history.
- [x] Generator: passwords, pronounceable passphrases and PINs, with exact entropy.
- [x] Strength estimate with plain-language feedback.
- [x] TOTP (RFC 6238), including otpauth:// links.
- [x] Clipboard copy that clears itself.
- [x] Audit: weak, reused, similar, old, and (online, k-anonymous) breached passwords.
- [x] Import from Bitwarden, Chrome, Firefox and 1Password. CSV/JSON export and encrypted
      backups.
