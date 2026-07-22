"""Terminal polish: ANSI colors, severity badges, ASCII banner.

Colors are enabled only on a real TTY. On Windows 10+ consoles virtual
terminal processing is switched on via SetConsoleMode. Output is plain
when piped or when NO_COLOR is set.
"""

import os
import sys

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
RED = "\x1b[31m"
ORANGE = "\x1b[38;5;208m"
YELLOW = "\x1b[33m"
BLUE = "\x1b[34m"
GRAY = "\x1b[90m"
GREEN = "\x1b[32m"
CYAN = "\x1b[36m"
MAGENTA = "\x1b[35m"

SEVERITY_COLORS = {
    "CRITICAL": RED,
    "HIGH": ORANGE,
    "MEDIUM": YELLOW,
    "SUSPICIOUS": MAGENTA,
    "LOW": BLUE,
    "UNKNOWN": GRAY,
}

BANNER = r"""
 __  __    _    _     _  ______
|  \/  |  / \  | |   | |/ / __ \
| |\/| | / _ \ | |   | ' / | | |
| |  | |/ ___ \| |___| . \ |_| |
|_|  |_/_/   \_\_____|_|\_\___/
   threat intelligence scanner
"""

_enabled = None


def _enable_windows_vt():
    """Enable ENABLE_VIRTUAL_TERMINAL_PROCESSING on stdout. Best-effort."""
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_ulong()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        if mode.value & 0x0004:  # already enabled
            return True
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except (AttributeError, OSError):
        return False


def _detect():
    if os.environ.get("NO_COLOR") is not None:
        return False
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        return _enable_windows_vt()
    return True


def colors_enabled():
    """Cached detection result (tests may reset via `_enabled = None`)."""
    global _enabled
    if _enabled is None:
        _enabled = _detect()
    return _enabled


def paint(text, *codes):
    """Wrap text in ANSI codes; returns it unchanged when colors are off."""
    if not codes or not colors_enabled():
        return text
    return "".join(codes) + str(text) + RESET


def badge(severity):
    """Colored [SEVERITY] badge; unknown severities render gray."""
    sev = (severity or "UNKNOWN").upper()
    return paint(f"[{sev}]", SEVERITY_COLORS.get(sev, GRAY), BOLD)


def banner():
    """Colored ASCII banner for interactive runs."""
    return paint(BANNER, CYAN)


def print_banner():
    """Print the banner only on interactive color-capable terminals."""
    if colors_enabled():
        print(banner())
