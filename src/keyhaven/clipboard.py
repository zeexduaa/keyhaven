"""Copying secrets to the clipboard, and clearing them again afterwards.

The clipboard is shared with every program on the desktop (and, on some systems,
synced to other devices or kept in a clipboard-history tool), so a copied password
should not stay there. After copying, keyhaven starts a small background process
that waits a few seconds and then clears the clipboard, but only if it still holds
what keyhaven put there: if you copied something else meanwhile, it is left alone.
The background process never gets the secret. It gets an HMAC of it under a random
one-time key, sent through a pipe rather than on its command line, because other
users can read command lines (``ps``) and a plain hash of a weak password is
easy to crack.

Each platform's own tool is used: pbcopy/pbpaste on macOS, wl-copy/wl-paste
(Wayland), xclip or xsel (X11) on Linux, and PowerShell on Windows.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass


class ClipboardError(RuntimeError):
    pass


@dataclass(frozen=True)
class Backend:
    name: str
    copy: list[str]
    paste: list[str]
    base64: bool = False        # the tool sends and receives base64 (see the PowerShell backend)


def _backends() -> list[Backend]:
    if sys.platform == "darwin":
        return [Backend("pbcopy", ["pbcopy"], ["pbpaste"])]
    if sys.platform == "win32":
        # Windows PowerShell decodes piped text in the console's legacy code page, not UTF-8,
        # so non-ASCII passwords would be garbled (and never recognised for clearing). The text
        # travels as base64 instead, which is plain ASCII. Set-Clipboard won't take an empty
        # string, so clearing uses the Forms API.
        ps = ["powershell", "-NoProfile", "-NonInteractive", "-Command"]
        copy_script = ("$t = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd().Trim())); "
                       "if ($t.Length) { Set-Clipboard -Value $t } "
                       "else { Add-Type -AssemblyName System.Windows.Forms; [Windows.Forms.Clipboard]::Clear() }")
        paste_script = ("$t = Get-Clipboard -Raw; if ($null -eq $t) { $t = '' }; "
                        "[Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($t)))")
        return [Backend("powershell", ps + [copy_script], ps + [paste_script], base64=True)]
    found = []
    if os.environ.get("WAYLAND_DISPLAY"):
        found.append(Backend("wl-clipboard", ["wl-copy"], ["wl-paste", "--no-newline"]))
    found.append(Backend("xclip", ["xclip", "-selection", "clipboard", "-in"], ["xclip", "-selection", "clipboard", "-out"]))
    found.append(Backend("xsel", ["xsel", "--clipboard", "--input"], ["xsel", "--clipboard", "--output"]))
    return found


def backend() -> Backend:
    for candidate in _backends():
        if shutil.which(candidate.copy[0]):
            return candidate
    hint = {"linux": "install wl-clipboard (Wayland) or xclip (X11)"}.get(sys.platform, "no clipboard tool was found")
    raise ClipboardError(f"can't reach the clipboard: {hint}. You can use 'show --reveal' instead.")


def copy(text: str, tool: Backend | None = None) -> None:
    tool = tool or backend()
    try:
        data = text.encode("utf-8")
        subprocess.run(tool.copy, input=base64.b64encode(data) if tool.base64 else data, check=True, timeout=10,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ClipboardError(f"copying with {tool.name} failed: {exc}") from None


def paste(tool: Backend | None = None) -> str:
    tool = tool or backend()
    try:
        result = subprocess.run(tool.paste, check=True, timeout=10, capture_output=True)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ClipboardError(f"reading the clipboard with {tool.name} failed: {exc}") from None
    data = result.stdout
    if tool.base64:
        try:
            data = base64.b64decode(data.strip(), validate=True)
        except ValueError:
            raise ClipboardError(f"{tool.name} returned something unreadable") from None
    return data.decode("utf-8", errors="replace")


def fingerprint(text: str, key: bytes) -> str:
    return hmac.new(key, text.encode("utf-8"), hashlib.sha256).hexdigest()


def clear_if_unchanged(expected: str, key: bytes, tool: Backend | None = None) -> bool:
    """Empties the clipboard if it still holds the text with this fingerprint."""
    tool = tool or backend()
    try:
        if not hmac.compare_digest(fingerprint(paste(tool), key), expected):
            return False
        copy("", tool)
        return True
    except ClipboardError:
        return False


def copy_and_clear_later(text: str, seconds: int) -> Backend:
    """Copies, then starts a detached process that clears the clipboard after ``seconds``."""
    tool = backend()
    copy(text, tool)
    if seconds > 0:
        key = secrets.token_bytes(32)
        args = [sys.executable, "-m", "keyhaven.clipboard", "--clear", str(seconds)]
        options: dict = {"stdin": subprocess.PIPE, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
                         "close_fds": True}
        if sys.platform == "win32":
            options["creationflags"] = 0x00000008 | 0x00000200      # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        else:
            options["start_new_session"] = True
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(p for p in [os.path.dirname(os.path.dirname(__file__)),
                                                          env.get("PYTHONPATH", "")] if p)
        helper = subprocess.Popen(args, env=env, **options)
        helper.stdin.write(f"{key.hex()} {fingerprint(text, key)}\n".encode("ascii"))
        helper.stdin.close()
    return tool


def _main(argv: list[str], stdin=None) -> int:
    """The helper: reads "KEY FINGERPRINT" from its standard input, waits, then clears."""
    if len(argv) != 2 or argv[0] != "--clear":
        print("usage: echo KEY FINGERPRINT | python -m keyhaven.clipboard --clear SECONDS", file=sys.stderr)
        return 2
    try:
        key_hex, expected = (stdin or sys.stdin).readline().split()
        key = bytes.fromhex(key_hex)
    except ValueError:
        return 2
    time.sleep(float(argv[1]))
    clear_if_unchanged(expected, key)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
