# DIRECTION CONTRACT — incident-report operator (grounded candidate 7, seed 3f8b5393).
# THESIS: the scan is an incident report, not a dashboard.
# OWN-WORLD: black ground, white ink, gray secondary; weight/rules/inverse video; severity as ASCII text, never hue.
# STORY: a beginner runs a full scan, reads findings as text, opens history, exports — keyboard only.
# FIRST VIEWPORT: inverse top bar, tab keyline, scan form with rules, live log, progress.
# FORM: typewriter incident-report. FINISH: unreviewed and undocumented is unfinished.
"""
tui.py — WebVAPT terminal entry point.

    python tui.py            # launch the black-and-white TUI
    python tui.py --check    # headless smoke check (no TTY needed)

The TUI is the primary interface. The plain CLI (scan.py) and the
FastAPI server (main.py) keep working alongside it.
"""

from __future__ import annotations

import sys


def main() -> None:
    if "--check" in sys.argv[1:] or "--help" in sys.argv[1:] or "-h" in sys.argv[1:]:
        _smoke()
        return
    from dotenv import load_dotenv

    load_dotenv()
    from tui.app import WebVaptApp

    WebVaptApp().run()


def _smoke() -> None:
    """Import everything and exercise the read-only backend paths."""
    from dotenv import load_dotenv

    load_dotenv()
    import tui.backend as B
    from tui.app import WebVaptApp

    d = B.defaults()
    assert isinstance(d["enable_ai"], bool) and isinstance(d["max_pages"], int)
    url, err = B.validate_target("")
    assert url == "" and err
    url, err = B.validate_target("example.com")
    assert url == "https://example.com" and err == ""
    stats = B.stats()
    assert {"total_scans", "total_findings"} <= set(stats)
    rows = B.list_scans(1)
    assert isinstance(rows, list)
    assert WebVaptApp.TITLE == "WEBVAPT"
    print(f"SMOKE OK  ai={d['enable_ai']} pages={d['max_pages']} scans={stats['total_scans']}")


if __name__ == "__main__":
    main()
