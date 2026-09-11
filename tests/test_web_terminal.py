"""Web terminal tests — page serves, websocket spawns a live TUI session."""

from fastapi.testclient import TestClient

from main import app


def test_terminal_page_serves():
    with TestClient(app) as client:
        r = client.get("/terminal")
        assert r.status_code == 200
        assert "xterm" in r.text
        assert "/ws/terminal" in r.text


def test_terminal_websocket_boots_tui():
    with TestClient(app) as client:
        with client.websocket_connect("/ws/terminal") as ws:
            buf = ""
            for _ in range(60):
                try:
                    buf += ws.receive_text()
                except Exception:
                    break
                if "WEBVAPT" in buf:
                    break
            assert "WEBVAPT" in buf, f"TUI banner missing; got {len(buf)} chars"
            # Keystrokes flow browser -> pty without error; TUI stays alive.
            ws.send_text("4")
            ws.send_text("1")
