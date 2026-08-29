"""
Clipboard copy with auto-clear (spec 5.1).

pyperclip needs a system clipboard backend (xclip/xsel/pbcopy/etc).
In headless/CI environments it isn't available — we degrade gracefully
rather than crash, since the CLI is a Week-1 scaffold; the PyQt6 GUI
in Week 2 has native clipboard access via QClipboard and will replace
this with a more robust implementation.
"""

import threading

try:
    import pyperclip
    _CLIPBOARD_AVAILABLE = True
except Exception:
    _CLIPBOARD_AVAILABLE = False

_clear_timer: threading.Timer | None = None


def copy_with_autoclear(secret: str, clear_after_seconds: int = 20) -> bool:
    """
    Copy `secret` to the clipboard and schedule it to be overwritten
    (not just "cleared" to empty — some clipboard managers keep history,
    so we overwrite with an empty string, which is the best a userland
    tool can do; document this limitation in the threat model).

    Returns True if the copy actually reached a system clipboard,
    False if we degraded to a no-op (e.g. headless environment).
    """
    global _clear_timer

    if _clear_timer is not None:
        _clear_timer.cancel()

    if not _CLIPBOARD_AVAILABLE:
        return False

    try:
        pyperclip.copy(secret)
    except Exception:
        return False

    def _clear():
        try:
            # Only clear if the clipboard still holds what we put there —
            # avoids clobbering something the user copied in the meantime.
            if pyperclip.paste() == secret:
                pyperclip.copy("")
        except Exception:
            # Deliberate best-effort swallow: this runs on a background
            # timer with no caller to report to. A failure here (e.g.
            # clipboard backend vanished) should not crash the app, and
            # there is nothing actionable to do besides leave the
            # clipboard as-is. Reviewed for bandit B110.
            pass  # nosec B110

    _clear_timer = threading.Timer(clear_after_seconds, _clear)
    _clear_timer.daemon = True
    _clear_timer.start()
    return True
