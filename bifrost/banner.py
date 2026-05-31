"""Bifrost startup ASCII banner with optional ANSI gradient."""

from __future__ import annotations

import os
import sys

DEFAULT_BANNER_VERSION = "0.3.0"

# Box width 64; inner art matches desktop / packaging branding.
_BANNER_TEMPLATE = """\
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗ ██╗███████╗██████╗  ██████╗ ███████╗████████╗     ║
║   ██╔══██╗██║██╔════╝██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝     ║
║   ██████╔╝██║█████╗  ██████╔╝██║   ██║███████╗   ██║        ║
║   ██╔══██╗██║██╔══╝  ██╔══██╗██║   ██║╚════██║   ██║        ║
║   ██████╔╝██║██║     ██║  ██║╚██████╔╝███████║   ██║        ║
║   ╚═════╝ ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝        ║
║                                                              ║
║              R A I N B O W   B R I D G E                     ║
║                                                              ║
║         Local AI-Powered Endpoint Detection & Response       ║
║                                                              ║
║                  The Bridge Is Watched                       ║
║                  Heimdall Never Sleeps                       ║
║                                                              ║
║                       v{version:<8}                          ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝"""

# Theme: purple #7B5EA7 → pink #C4607A
_PURPLE = (123, 94, 167)
_PINK = (196, 96, 122)
_BORDER = (90, 70, 130)
_MUTED = (160, 140, 180)


def _stdout_is_tty() -> bool:
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


def _truecolor(r: int, g: int, b: int) -> str:
    return f"\033[38;2;{r};{g};{b}m"


def _lerp_rgb(t: float) -> tuple[int, int, int]:
    t = max(0.0, min(1.0, t))
    return (
        int(_PURPLE[0] + (_PINK[0] - _PURPLE[0]) * t),
        int(_PURPLE[1] + (_PINK[1] - _PURPLE[1]) * t),
        int(_PURPLE[2] + (_PINK[2] - _PURPLE[2]) * t),
    )


def _colorize_line(line: str, index: int, total: int) -> str:
    stripped = line.strip()
    if not stripped:
        return line
    if stripped.startswith("╔") or stripped.startswith("╚") or stripped == "║":
        return _truecolor(*_BORDER) + line + "\033[0m"
    if "████" in line or "██╔" in line or "██║" in line or "╚══" in line:
        t = index / max(1, total - 1)
        rgb = _lerp_rgb(t)
        return _truecolor(*rgb) + line + "\033[0m"
    if "R A I N B O W" in line:
        return _truecolor(*_PINK) + line + "\033[0m"
    if line.strip().startswith("║                  The Bridge"):
        return _truecolor(*_PURPLE) + line + "\033[0m"
    if "Heimdall Never" in line:
        return _truecolor(*_PINK) + line + "\033[0m"
    if stripped.startswith("║         Local AI"):
        return _truecolor(*_MUTED) + line + "\033[0m"
    if "v" in line and "║" in line:
        return _truecolor(*_PINK) + line + "\033[0m"
    return _truecolor(*_MUTED) + line + "\033[0m"


def banner_text(version: str = DEFAULT_BANNER_VERSION) -> str:
    return _BANNER_TEMPLATE.format(version=version)


def print_startup_banner(
    version: str = DEFAULT_BANNER_VERSION,
    *,
    force: bool = False,
) -> None:
    """Print the Bifrost banner once when stdout is an interactive terminal."""
    if os.environ.get("BIFROST_NO_BANNER"):
        return
    if not force and not _stdout_is_tty():
        return
    text = banner_text(version)
    if not _stdout_is_tty():
        print(text, flush=True)
        return
    lines = text.splitlines()
    total = len(lines)
    for i, line in enumerate(lines):
        print(_colorize_line(line, i, total), flush=True)
    print("\033[0m", flush=True)


def main() -> None:
    print_startup_banner(force=True)


if __name__ == "__main__":
    main()
