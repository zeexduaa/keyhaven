"""Copying secrets to the clipboard, and clearing them again afterwards.

The clipboard is shared with every program on the desktop (and, on some systems,
synced to other devices or kept in a clipboard-history tool), so a copied password
should not stay there. After copying, keyhaven starts a small background process
that waits a few seconds and then clears the clipboard, but only if it still holds
what keyhaven put there: if you copied something else meanwhile, it is left alone.
The background process is given a hash of the secret, never the secret itself.

Each platform's own tool is used: pbcopy/pbpaste on macOS, wl-copy/wl-paste
(Wayland), xclip or xsel (X11) on Linux, and PowerShell on Windows.
"""

from __future__ import annotations

import hashlib
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


def _backends() -> list[Backend]:
    if sys.platform == "darwin":
        return [Backend("pbcopy", ["pbcopy"], ["pbpaste"])]
    if sys.platform == "win32":
        ps = ["powershell", "-NoProfile", "-NonInteractive", "-Command"]
        return [Backend("powershell", ps + ["$input | Set-Clipboard"], ps + ["Get-Clipboard -Raw"])]
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
        subprocess.run(tool.copy, input=text.encode("utf-8"), check=True, timeout=10,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ClipboardError(f"copying with {tool.name} failed: {exc}") from None


def paste(tool: Backend | None = None) -> str:
    tool = tool or backend()
    try:
        result = subprocess.run(tool.paste, check=True, timeout=10, capture_output=True)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ClipboardError(f"reading the clipboard with {tool.name} failed: {exc}") from None
    text = result.stdout.decode("utf-8", errors="replace")
    return text[:-2] if text.endswith("\r\n") else text      # PowerShell adds a line break


def fingerprint(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def clear_if_unchanged(expected: str, tool: Backend | None = None) -> bool:
    """Empties the clipboard if it still holds the text with this fingerprint."""
    tool = tool or backend()
    try:
        if fingerprint(paste(tool)) != expected:
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
        args = [sys.executable, "-m", "keyhaven.clipboard", "--clear", fingerprint(text), str(seconds)]
        options: dict = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
                         "close_fds": True}
        if sys.platform == "win32":
            options["creationflags"] = 0x00000008 | 0x00000200      # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        else:
            options["start_new_session"] = True
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(p for p in [os.path.dirname(os.path.dirname(__file__)),
                                                          env.get("PYTHONPATH", "")] if p)
        subprocess.Popen(args, env=env, **options)
    return tool


def _main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[0] != "--clear":
        print("usage: python -m keyhaven.clipboard --clear FINGERPRINT SECONDS", file=sys.stderr)
        return 2
    time.sleep(float(argv[2]))
    clear_if_unchanged(argv[1])
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
