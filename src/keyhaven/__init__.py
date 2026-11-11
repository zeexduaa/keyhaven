"""keyhaven: a local, encrypted password manager.

The vault is one file, encrypted with AES-256-GCM under a random data key; the
data key is encrypted with a key derived from your master password by scrypt.
See docs/security.md for the design and its limits.
"""

__version__ = "0.1.0"
