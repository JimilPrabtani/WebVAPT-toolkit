"""
tui/app.py
──────────
Monochrome Textual TUI for WebVAPT-toolkit (Operate surface).

World: typewriter incident-report — black ground, white ink, gray
secondary. Hierarchy from weight, hairline rules, and inverse video.
Severity is ASCII text ([!!]/[!]/[*]/[.]/[i]), never colour.

Screens (keys 1-4):
  1 SCAN    — target form + live log + progress
  2 RESULTS — summary + findings table + detail + filters (render_results)
  3 HISTORY — past scans + view/delete/export (tab_history + sidebar)
  4 HELP    — workflow + legal (tab_about)

Backend: tui/backend.py → scanner.engine.run_scan() in a worker thread.
"""

from __future__ import annotations

from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Input,
    ProgressBar,
    RichLog,
    Select,
    Static,
    TabbedContent,
    TabPane,
)

from tui import backend as B

CATEGORIES = [
    ("All categories", "ALL"),
    ("Injection", "Injection"),
    ("XSS", "Cross-Site Scripting"),
    ("Security Headers", "Header"),
    ("Cookies", "Cookie"),
    ("TLS / HTTPS", "TLS"),
    ("Secrets", "Secret"),
    ("Exposed Files", "Exposure"),
    ("Info", "Information"),
]


class WebVaptApp(App):
    """Black-and-white scan operator."""

    CSS_PATH = "theme.tcss"
    TITLE = "WEBVAPT"

    BINDINGS = [
        ("1", "tab('scan')", "Scan"),
        ("2", "tab('results')", "Results"),
        ("3", "tab('history')", "History"),
        ("4", "tab('help')", "Help"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.scan: dict | None = None
        self.scanning = False
        self._ai_only = False
        self._sev_on = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        self._cat = "ALL"

    # ── layout ──────────────────────────────────────────────
    def compose(self) -> ComposeResult:
        yield Static(" WEBVAPT // TERMINAL  —  authorized testing only ", id="topbar")
        yield Static(
            "[1] SCAN   [2] RESULTS   [3] HISTORY   [4] HELP",
            id="tabbar",
        )
        with TabbedContent(initial="scan"):
            with TabPane("Scan", id="scan"):
                yield Static("NEW SCAN", classes="panel-title")
                yield Static(
                    "Enter a target. The tool crawls it, runs all checks, "
                    "optionally asks AI for fixes, then saves everything.",
                    classes="dim",
                )
                yield Static("-" * 60, classes="rule")
                yield Static("TARGET URL", classes="dim")
                yield Input(placeholder="https://example.com", id="target")
                yield Checkbox("AI analysis (fixes + risk score)", value=True, id="ai")
                yield Static("PAGES TO CRAWL (1-50)", classes="dim")
                yield Input(value="20", id="pages", max_length=3)
                yield Button("START SCAN  [Enter]", id="start", variant="default")
                yield Static("LIVE LOG", classes="panel-title")
                yield RichLog(id="log", wrap=True, markup=False)
                yield ProgressBar(total=100, show_eta=False, id="bar")
                yield Static("", id="scanmsg", classes="dim")
            with TabPane("Results", id="results"):
                yield Static("RESULTS", classes="panel-title")
                yield Static("No scan loaded yet. Run a scan or open one from History.", id="summary", classes="dim")
                yield Static("-" * 60, classes="rule")
                with Horizontal():
                    yield Select(CATEGORIES, value="ALL", id="cat", prompt="Category")
                    yield Checkbox("AI-verified only", value=False, id="aionly")
                yield DataTable(id="findings")
                yield Static("DETAIL (select a row)", classes="panel-title")
                yield Static("-", id="detail")
            with TabPane("History", id="history"):
                yield Static("HISTORY", classes="panel-title")
                yield Static("Every completed scan is stored locally (SQLite).", classes="dim")
                yield Static("-" * 60, classes="rule")
                yield DataTable(id="scans")
                with Horizontal():
                    yield Button("Open", id="open")
                    yield Button("Delete", id="delete")
                    yield Button("Refresh", id="refresh")
                yield Static("", id="histmsg", classes="dim")
            with TabPane("Help", id="help"):
                yield Static("HOW IT WORKS", classes="panel-title")
                yield Static("-" * 60, classes="rule")
                yield Static(
                    "1. CRAWL — breadth-first walk of the target domain.\n"
                    "2. SCAN — 30+ checks in 7 groups: headers, injection, "
                    "XSS, secrets, TLS, open redirect, misconfiguration.\n"
                    "3. DEDUP — identical findings collapse to one.\n"
                    "4. AI — HIGH/CRITICAL/MEDIUM go to AI for CVSS, "
                    "attack scenario, and fix steps.\n"
                    "5. SAVE — SQLite record plus JSON + TXT in data/reports/.\n"
                    "\n"
                    "KEYS — 1/2/3/4 switch tabs. Tab moves focus. "
                    "Enter activates. Q quits.\n"
                    "\n"
                    "LEGAL — authorized testing only. "
                    "Get written permission before scanning a target you do not own."
                )

        yield Static("", id="statusline")
        yield Footer()

    def on_mount(self) -> None:
        findings: DataTable = self.query_one("#findings", DataTable)
        findings.add_columns("SEV", "TYPE", "URL", "CVSS", "AI")
        findings.cursor_type = "row"
        scans: DataTable = self.query_one("#scans", DataTable)
        scans.add_columns("ID", "TARGET", "STATUS", "RISK", "SCORE", "N", "STARTED")
        scans.cursor_type = "row"
        self._status("Ready. Tab 1 to scan.")
        self._refresh_history()

    # ── helpers ─────────────────────────────────────────────
    def _status(self, msg: str) -> None:
        self.query_one("#statusline", Static).update(f" {msg}")

    def _log(self, msg: str) -> None:
        self.query_one("#log", RichLog).write(msg)

    def _typing(self) -> bool:
        """True while focus is in a text field — single-key shortcuts yield."""
        return isinstance(self.focused, (Input, Select))

    def action_tab(self, name: str) -> None:
        if self._typing():
            return  # keystroke belongs to the field, not the tab bar
        self.query_one(TabbedContent).active = name

    def action_quit(self) -> None:
        if self._typing():
            return  # e.g. typing "q" in the URL field must not quit
        self.exit()

    # ── scan ────────────────────────────────────────────────
    @on(Button.Pressed, "#start")
    def start_pressed(self) -> None:
        if self.scanning:
            return
        target = self.query_one("#target", Input).value
        url, err = B.validate_target(target)
        if err:
            self.query_one("#scanmsg", Static).update(err)
            return
        try:
            pages = max(1, min(50, int(self.query_one("#pages", Input).value or "20")))
        except ValueError:
            pages = 20
        ai = self.query_one("#ai", Checkbox).value
        self.scanning = True
        self.query_one("#scanmsg", Static).update(f"Scanning {url} ...")
        self.query_one("#log", RichLog).clear()
        self._log(f"$ scan {url}  (ai={'on' if ai else 'off'}, pages={pages})")
        self._status("Scanning ...")
        self._run_scan(url, ai, pages)

    @work(thread=True, exclusive=True)
    def _run_scan(self, url: str, ai: bool, pages: int) -> None:
        log = lambda m: self.call_from_thread(self._log, str(m))
        try:
            scan_id = B.create_scan_record(url)
            result, exec_summary = B.run_scan_direct(url, ai, pages, on_progress=log)
            if result.error:
                self.call_from_thread(self._scan_failed, result.error)
                return
            paths = B.persist(scan_id, result, exec_summary or {})
            data = B.get_scan(scan_id)
            self.call_from_thread(self._scan_done, data, paths)
        except Exception as e:  # never strand the UI in "scanning"
            self.call_from_thread(self._scan_failed, str(e))

    def _scan_failed(self, err: str) -> None:
        self.scanning = False
        self.query_one("#scanmsg", Static).update(f"FAILED: {err}")
        self._status("Scan failed.")
        self.query_one("#bar", ProgressBar).update(total=100, progress=0)

    def _scan_done(self, data: dict | None, paths: dict) -> None:
        self.scanning = False
        self.query_one("#bar", ProgressBar).update(total=100, progress=100)
        if not data:
            self.query_one("#scanmsg", Static).update("Scan finished but record missing.")
            return
        self.scan = data
        self._render_results()
        self._refresh_history()
        msg = f"Done: {data.get('total_findings', 0)} findings. JSON: {paths.get('json','')}"
        self.query_one("#scanmsg", Static).update(msg)
        self._status("Scan complete. Tab 2 for results.")
        self.query_one(TabbedContent).active = "results"

    # ── results ─────────────────────────────────────────────
    def _render_results(self) -> None:
        if not self.scan:
            return
        self.query_one("#summary", Static).update(B.summary_text(self.scan))
        table: DataTable = self.query_one("#findings", DataTable)
        table.clear()
        for f in self.scan.get("findings", []):
            if f.get("severity") not in self._sev_on:
                continue
            if self._ai_only and f.get("ai_verified") != 1:
                continue
            if self._cat != "ALL" and self._cat not in (f.get("vuln_type") or ""):
                continue
            table.add_row(*B.finding_to_row(f))

    @on(DataTable.RowSelected, "#findings")
    def finding_selected(self, event: DataTable.RowSelected) -> None:
        if not self.scan:
            return
        # Re-derive the visible list in the same order used to fill the table.
        visible = [
            f
            for f in self.scan.get("findings", [])
            if f.get("severity") in self._sev_on
            and (not self._ai_only or f.get("ai_verified") == 1)
            and (self._cat == "ALL" or self._cat in (f.get("vuln_type") or ""))
        ]
        if 0 <= event.cursor_row < len(visible):
            self.query_one("#detail", Static).update(
                B.finding_detail_text(visible[event.cursor_row])
            )

    @on(Select.Changed, "#cat")
    def cat_changed(self, event: Select.Changed) -> None:
        self._cat = str(event.value)
        self._render_results()

    @on(Checkbox.Changed, "#aionly")
    def aionly_changed(self, event: Checkbox.Changed) -> None:
        self._ai_only = bool(event.value)
        self._render_results()

    # ── history ─────────────────────────────────────────────
    def _refresh_history(self) -> None:
        table: DataTable = self.query_one("#scans", DataTable)
        table.clear()
        try:
            rows = B.list_scans(50)
        except Exception as e:
            self.query_one("#histmsg", Static).update(f"History unavailable: {e}")
            return
        for s in rows:
            table.add_row(
                (s.get("id") or "")[:8],
                (s.get("target_url") or "")[:40],
                s.get("status") or "",
                s.get("overall_risk") or "-",
                str(s.get("risk_score") if s.get("risk_score") is not None else "-"),
                str(s.get("total_findings", 0)),
                (s.get("started_at") or "")[:16].replace("T", " "),
            )
        table._full = rows  # stash full rows for open/delete

    @on(Button.Pressed, "#refresh")
    def refresh_pressed(self) -> None:
        self._refresh_history()
        self._status("History refreshed.")

    def _selected_scan_id(self) -> tuple[str, dict | None]:
        table: DataTable = self.query_one("#scans", DataTable)
        rows: list = getattr(table, "_full", [])
        if not rows or table.cursor_row is None or table.cursor_row < 0:
            return "", None
        if table.cursor_row >= len(rows):
            return "", None
        full = rows[table.cursor_row]
        return full.get("id", ""), full

    @on(Button.Pressed, "#open")
    def open_pressed(self) -> None:
        scan_id, _ = self._selected_scan_id()
        if not scan_id:
            self.query_one("#histmsg", Static).update("Select a row first.")
            return
        data = B.get_scan(scan_id)
        if not data:
            self.query_one("#histmsg", Static).update("Could not load scan.")
            return
        self.scan = data
        self._render_results()
        self.query_one(TabbedContent).active = "results"
        self._status("Loaded scan. Tab 2.")

    @on(Button.Pressed, "#delete")
    def delete_pressed(self) -> None:
        scan_id, full = self._selected_scan_id()
        if not scan_id:
            return
        label = (full or {}).get("target_url", scan_id[:8])
        if getattr(self, "_confirm_delete", "") == scan_id:
            ok = B.delete_scan_record(scan_id)
            self._confirm_delete = ""
            self.query_one("#histmsg", Static).update(
                f"Deleted {label}." if ok else "Delete failed."
            )
            self._refresh_history()
        else:
            self._confirm_delete = scan_id
            self.query_one("#histmsg", Static).update(
                f"Press Delete again to confirm removal of {label}."
            )
