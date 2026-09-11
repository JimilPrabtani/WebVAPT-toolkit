"""TUI tests — headless Pilot: boot, navigate tabs, filter, history."""

import pytest
from textual.widgets import Input

from tui import backend as B
from tui.app import WebVaptApp


def test_backend_defaults():
    d = B.defaults()
    assert isinstance(d["enable_ai"], bool)
    assert 1 <= d["max_pages"] <= 50


def test_validate_target():
    url, err = B.validate_target("example.com")
    assert url == "https://example.com" and err == ""
    _, err = B.validate_target("")
    assert err


def test_severity_tag_ascii():
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        tag = B.severity_tag(sev)
        assert tag.startswith("[") and tag.endswith("]")
        tag.encode("ascii")  # no emoji, no colour codes


@pytest.mark.asyncio
async def test_app_boots_and_switches_tabs():
    app = WebVaptApp()
    async with app.run_test() as pilot:
        assert app.query_one("#target")
        assert app.query_one("#findings")
        assert app.query_one("#scans")
        await pilot.press("2")
        assert app.query_one("TabbedContent").active == "results"
        await pilot.press("3")
        assert app.query_one("TabbedContent").active == "history"
        await pilot.press("1")
        assert app.query_one("TabbedContent").active == "scan"


@pytest.mark.asyncio
async def test_typing_in_field_does_not_switch_tabs_or_quit():
    app = WebVaptApp()
    async with app.run_test() as pilot:
        await pilot.click("#target")
        await pilot.press("2")
        assert app.query_one("TabbedContent").active == "scan"
        assert app.query_one("#target", Input).value == "2"
        await pilot.press("q")
        assert app.query_one("TabbedContent").active == "scan"
        assert app.query_one("#target", Input).value == "2q"
        assert app.is_running  # q while typing must not quit


@pytest.mark.asyncio
async def test_results_render_from_fixture():
    app = WebVaptApp()
    async with app.run_test() as pilot:
        app.scan = {
            "target_url": "https://example.com",
            "status": "complete",
            "pages_crawled": 3,
            "duration_secs": 12.0,
            "risk_score": 75,
            "overall_risk": "HIGH",
            "total_findings": 2,
            "summary_json": {"by_severity": {"CRITICAL": 1, "HIGH": 1}},
            "exec_summary": {"executive_summary": "Test summary."},
            "findings": [
                {
                    "severity": "CRITICAL",
                    "vuln_type": "SQL Injection (Error-Based)",
                    "url": "https://example.com/?id=1",
                    "detail": "d",
                    "evidence": "e",
                    "remediation": "",
                    "ai_verified": 1,
                    "cvss_score": 9.1,
                },
                {
                    "severity": "LOW",
                    "vuln_type": "Information Disclosure: Server",
                    "url": "https://example.com/",
                    "detail": "d2",
                    "evidence": "e2",
                    "remediation": "",
                    "ai_verified": 0,
                    "cvss_score": None,
                },
            ],
        }
        app._render_results()
        await pilot.pause()
        assert app.query_one("#findings").row_count == 2
        app._ai_only = True
        app._render_results()
        await pilot.pause()
        assert app.query_one("#findings").row_count == 1
