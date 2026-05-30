#!/usr/bin/env python3
"""One-command Bifrost launcher: start guardian + open dashboard."""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def _default_dashboard_url(port: int | None = None) -> str:
    resolved_port = port or int(os.getenv("BIFROST_DASHBOARD_PORT", "8766") or "8766")
    host = os.getenv("BIFROST_DASHBOARD_HOST", "").strip() or "127.0.0.1"
    return f"http://{host}:{resolved_port}/"


def _wait_for_dashboard(url: str, timeout: float = 45.0) -> bool:
    health = url.rstrip("/") + "/healthz"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(health, timeout=2) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, TimeoutError, OSError):
            pass
        time.sleep(0.4)
    return False


def _open_dashboard(url: str, *, desktop: bool) -> None:
    if desktop:
        try:
            import webview

            webview.create_window(
                "Bifrost — Heimdall Security Dashboard",
                url,
                width=1400,
                height=900,
                resizable=True,
            )
            webview.start()
            return
        except ImportError:
            logging.warning("pywebview not installed — opening system browser.")
        except Exception as exc:
            logging.warning("Desktop window failed: %s — opening browser.", exc)

    import webbrowser

    webbrowser.open(url)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="bifrost",
        description="Start Bifrost guardian and open the security dashboard.",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Start guardian only; do not open a browser or desktop window.",
    )
    parser.add_argument(
        "--desktop",
        action="store_true",
        help="Open dashboard in a pywebview desktop window (if installed).",
    )
    parser.add_argument(
        "--dashboard-port",
        type=int,
        default=None,
        help="Dashboard listen port (default 8766).",
    )
    parser.add_argument(
        "guardian_args",
        nargs=argparse.REMAINDER,
        help="Extra arguments passed to bifrost.guardian",
    )
    args = parser.parse_args(argv)

    project_root = Path(__file__).resolve().parent.parent
    env = os.environ.copy()
    port = args.dashboard_port or int(env.get("BIFROST_DASHBOARD_PORT", "8766") or "8766")
    env["BIFROST_DASHBOARD_PORT"] = str(port)

    cmd = [sys.executable, "-m", "bifrost.guardian", "--dashboard", "--dashboard-port", str(port)]
    if args.guardian_args:
        cmd.extend(args.guardian_args)

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    log = logging.getLogger("bifrost.cli")

    proc = subprocess.Popen(
        cmd,
        cwd=str(project_root),
        env=env,
        start_new_session=True,
    )

    url = _default_dashboard_url(port)
    if not args.no_browser:
        if _wait_for_dashboard(url):
            _open_dashboard(url, desktop=args.desktop)
        else:
            log.warning("Dashboard did not become ready in time: %s", url)

    print(f"Bifrost is running — dashboard at {url.rstrip('/')}")

    try:
        return proc.wait()
    except KeyboardInterrupt:
        print("\nShutting down Bifrost…")
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
