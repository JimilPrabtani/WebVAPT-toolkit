"""
api/terminal.py
───────────────
Web terminal: the SAME Textual TUI (`python tui.py`) rendered in a browser.

  GET /terminal      → fullscreen xterm.js page (black ground, white ink)
  WS  /ws/terminal   → one private TUI session per connection

Each websocket spawns `sys.executable tui.py` inside a ConPTY (pywinpty),
so Textual sees a real console and renders exactly as in a local terminal.
Keystrokes stream browser → pty, screen bytes stream pty → browser.
A JSON `{"resize": [cols, rows]}` message resizes the pty.

Nothing about scanning changes: the child process runs the same
tui/backend.py → scanner.engine.run_scan() pipeline and writes to the
same SQLite database and data/reports/ files.

SECURITY: anyone who can reach these endpoints gets an interactive
scanner (same power as sitting at the server's keyboard — TUI only,
not a shell, but scans can target any URL the SSRF guard allows).
Bind uvicorn to 127.0.0.1 by default; put authentication (reverse
proxy / VPN / SSH tunnel) in front before exposing to a network.
"""

from __future__ import annotations

import json
import os
import signal
import sys
from pathlib import Path

import anyio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

router = APIRouter()

_HTML = Path(__file__).parent.parent / "web" / "terminal.html"
_PROJECT_ROOT = Path(__file__).parent.parent


@router.get("/terminal", summary="Web terminal running the TUI")
def terminal_page() -> HTMLResponse:
    """Serve the xterm.js page that hosts one private TUI session."""
    return HTMLResponse(_HTML.read_text(encoding="utf-8"))


def _spawn_tui(cols: int, rows: int):
    """Spawn `python tui.py` in a ConPTY. Returns (proc, env-ok)."""
    from winpty import PtyProcess

    env = dict(os.environ)
    env["TERM"] = "xterm-256color"
    proc = PtyProcess.spawn(
        [sys.executable, "tui.py"],
        cwd=str(_PROJECT_ROOT),
        env=env,
    )
    proc.setwinsize(rows, cols)
    return proc


@router.websocket("/ws/terminal")
async def terminal_socket(ws: WebSocket) -> None:
    """Pump bytes between the browser terminal and one TUI child process."""
    await ws.accept()
    try:
        import winpty  # noqa: F401 — Windows-only ConPTY backend
    except ImportError:  # pragma: no cover — Windows-only dependency
        await ws.close(code=1013, reason="pywinpty not installed (Windows only)")
        return

    proc = await anyio.to_thread.run_sync(_spawn_tui, 120, 32)
    alive = True

    async def pty_to_ws() -> None:
        try:
            while alive and proc.isalive():
                chunk = await anyio.to_thread.run_sync(proc.read, 65536)
                if chunk:
                    await ws.send_text(chunk)
                else:
                    await anyio.sleep(0.05)
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            # Child quit (e.g. Q in the TUI): tell the browser instead of
            # leaving it frozen on the last frame.
            if alive:
                try:
                    await ws.send_text(
                        "\r\n\r\n[ session ended — reload the page for a new TUI ]\r\n"
                    )
                except (WebSocketDisconnect, RuntimeError):
                    pass

    async def ws_to_pty() -> None:
        nonlocal alive
        try:
            while alive:
                msg = await ws.receive_text()
                try:
                    ctl = json.loads(msg)
                    if isinstance(ctl, dict) and "resize" in ctl:
                        cols, rows = (int(x) for x in ctl["resize"][:2])
                        proc.setwinsize(max(1, rows), max(1, cols))
                        continue
                except (ValueError, TypeError):
                    pass
                await anyio.to_thread.run_sync(proc.write, msg)
        except WebSocketDisconnect:
            pass
        finally:
            alive = False

    try:
        async with anyio.create_task_group() as tg:
            tg.start_soon(pty_to_ws)
            tg.start_soon(ws_to_pty)
    finally:
        alive = False
        try:
            if proc.isalive():
                await anyio.to_thread.run_sync(proc.kill, signal.SIGTERM)
        except Exception:
            pass  # already dead or reaped — nothing to clean up
        try:
            await ws.close()
        except (WebSocketDisconnect, RuntimeError):
            pass  # client already gone
