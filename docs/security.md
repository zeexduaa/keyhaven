# keyhaven security design

This page explains what keyhaven protects against, how it does it, and, just as
important, what it does **not** protect against. If you find a mistake, please
open an issue (or, for something serious, contact the maintainer privately
first).

## What it protects

keyhaven keeps your entries in one file. The goal is that **someone who gets a
copy of that file learns nothing useful** without your master password: not
your passwords, usernames, sites, notes or tags, and not even how many entries
there are beyond a rough size.

Typical ways a copy could be taken: a stolen or lost laptop, a backup drive,
a cloud-synced folder, malware that grabs files but does not watch you type.

## How the file is protected

```
master password ──scrypt(salt, N=2^17, r=8, p=1)──► key-encryption key (KEK)
                                                         │ AES-256-GCM
                                                         ▼
                          data key (32 random bytes) ◄── "key" section
                                │ AES-256-GCM
                                ▼
                          entries (JSON) ◄── "data" section
```

- **Key stretching.** The master password goes through scrypt with a random
  16-byte salt. The default cost uses 128 MiB of memory and about 0.4 s per try
  on a laptop. An attacker who has the file has to pay the same for *every*
  guess, and the memory cost makes GPUs and ASICs much less effective than
  against fast hashes. The password is NFKC-normalized first, so the same
  password typed on different keyboards or systems gives the same key.
- **Two keys.** A random *data key* encrypts the entries, and the KEK encrypts
  only the data key. Changing the master password re-encrypts 32 bytes with a
  new salt. The entries are never re-encrypted under a half-finished key.
- **Authenticated encryption.** Both sections use AES-256-GCM with a new random
  96-bit nonce on every save. Any change to a ciphertext or nonce makes opening
  fail. keyhaven never decrypts to garbage.
- **The header is authenticated too.** The format, version, scrypt settings and
  cipher name are not secret, but they are the *associated data* of both
  encryptions. Someone who edits the header, for example to lower the scrypt
  cost so the next save is weaker, makes the file fail to open. Each section's
  associated data also says which section it is, so the two ciphertexts can't
  be swapped.
- **Hostile headers.** The scrypt settings are checked before they are used.
  N must be a power of two from 2^10 to 2^22, r is 1 to 32, p is 1 to 16, and
  memory use is at most 1 GiB. A crafted file therefore can't make keyhaven use
  all the memory, or open with a trivially weak setting.
- **Clear error messages that leak nothing useful.** A wrong password and a
  damaged file are told apart only after the data key has decrypted. At that
  point the password is known to be right, so saying "the entries are damaged,
  try the backup" gives an attacker nothing.

All cryptography comes from the `cryptography` package (OpenSSL), Python's
`hashlib.scrypt` (OpenSSL) and `secrets` (the OS random source). Nothing is
hand-written.

## Saving safely

- Saves are **atomic**: keyhaven writes a temporary file, flushes it to disk,
  renames it over the vault and flushes the folder. A crash or power cut leaves
  the old vault or the new one, never half of each.
- The previous version is kept as `vault.json.bak`. It opens with the master
  password that was in use when it was written.
- On Unix the file is created with mode `0600`, so only you can read it.
  `keyhaven info` warns if the permissions have been loosened.
- A **lock file** (`vault.json.lock`) stops two keyhaven commands from saving
  over each other's changes. A lock left by a crashed process on the same
  machine is detected and taken over.

## The command line

- The master password is read only from the terminal, without echo. It is
  never taken from an argument or an environment variable, where it would be
  visible in shell history or in the process list.
- `show` hides the password unless you ask for `--reveal`.
- `copy` puts the secret on the clipboard and starts a background helper that
  clears it after 20 seconds (`keyhaven set clipboard_seconds N`). The helper
  only clears the clipboard if it still holds that secret, so it won't wipe
  something you copied since. The helper is given a SHA-256 hash of the
  secret, never the secret itself.
- `export` writes plain text and needs an explicit yes. It won't overwrite an
  existing file and creates the file readable only by you. `import` reminds
  you to delete the plain-text file it read.
- `audit --online` checks passwords against Have I Been Pwned with
  *k-anonymity*: only the first 5 hex characters of each SHA-1 hash are sent,
  with response padding. The service never sees a password or a full hash.
  Without `--online`, keyhaven makes no network connections at all.

## What it does NOT protect against

Be honest with yourself about these:

- **A weak master password.** scrypt makes every guess expensive, but a
  password from a list of common ones will still be found. Use a passphrase of
  five or more random words (`keyhaven generate --words 5`). keyhaven warns
  when you choose a weak one.
- **Malware or someone with control of your logged-in computer.** A keylogger
  sees the master password as you type it. Anything that can read keyhaven's
  memory while it runs, or watch the clipboard, sees secrets as they are used.
  No password manager can defend against a fully compromised machine.
- **Secrets left in memory.** Python can't reliably wipe memory: strings are
  immutable and may be copied by the runtime. Decrypted entries live in the
  process memory until it exits (each command is short-lived), and may reach
  swap or a crash dump. Use full-disk encryption, which also protects swap.
- **Clipboard managers and sync.** Clipboard-history tools and "universal
  clipboard" features may keep or sync a copied password before keyhaven
  clears it. Turn them off, or use `show --reveal` and type the password.
- **Two-factor secrets in the same vault.** Storing TOTP secrets in keyhaven
  is convenient. It also means that anyone who opens the vault has both
  factors. For your most important accounts (email, bank), consider keeping
  2FA on a separate device.
- **Forgetting the master password.** There is no recovery and no back door,
  by design. Keep a written copy somewhere physically safe if you are worried.
- **Losing the file.** keyhaven keeps one `.bak`, which is not a backup
  strategy. Run `keyhaven backup <folder>` to a drive or another location
  regularly. The copies are encrypted.
- **Metadata.** The file's size, modification time and scrypt settings are
  visible. The number of entries can be roughly estimated from the size.
- **Rollback.** Someone who can write to your files could replace the vault
  with an older copy of itself, which still opens with your password. keyhaven
  does not detect this yet (see the roadmap).

## Not yet done

These are planned and are listed in [ROADMAP.md](../ROADMAP.md). Until then,
keyhaven does not have them:

- Argon2id as an alternative key derivation function.
- Hardware keys (FIDO2 / YubiKey) as a second factor for opening the vault.
- Detecting rollback to an older vault.
- A security review by someone other than its authors. Until one happens,
  treat keyhaven as young software.
