# Design

<!-- impeccable:design-schema 1 -->

## World

Incident-report operator. The scan is a typewritten report, not a dashboard:
black ground, white ink, gray secondary. No accent colour exists on purpose.

## Palette

Ground `#000000`. Ink `#FFFFFF`. Secondary `#9a9a9a` (labels, rules, dim copy).
Structure `#2a2a2a` (selected table row). Near-blacks from the terminal only.
Severity is ASCII text — `[!!] CRITICAL`, `[!] HIGH`, `[*] MEDIUM`,
`[.] LOW`, `[i] INFO` — never hue. Verified achromatic via screenshot
palette audit (`.impeccable/review/tui-*.svg`).

## Typography

Terminal monospace throughout (client font). One scale: bold panel titles,
regular body, dim micro-labels in caps. No display face — this is an Operate
surface; scanability outranks expression.

## Composition

Inverse top bar (`WEBVAPT // TERMINAL — authorized testing only`), numeric
tab keyline (`[1] SCAN [2] RESULTS [3] HISTORY [4] HELP`), hairline rules
between sections, boxed inputs, inverse footer with key bindings.
Textual's own tab strip is hidden (`Tabs { display: none }`) — the keyline
is the tab UI. First viewport: scan form, live log, progress.

## Controls & States

Inputs/checkboxes/selects: hairline gray border, white border on focus.
Buttons: bordered; inverse (white ground, black text, bold) on focus/hover.
Tables: inverse header row; selected row `#2a2a2a`. Checkbox mark: white
`X` on black. Scan runs in a worker thread; live log streams via
`call_from_thread`; failure returns the UI to idle with an error line —
never stranded in "scanning". Delete is two-step confirm. Empty states:
"No scan loaded yet", "Select a row first".

## Surfaces

- `tui.py` — entry (`python tui.py`, `python tui.py --check` smoke).
- `tui/app.py` — `WebVaptApp`, four tabs, key bindings 1-4/Q.
- `tui/backend.py` — adapter to `scanner.engine.run_scan()`,
  `api/database.py`, `reports/report_writer.py`. No parallel scan logic.
- `tui/theme.tcss` — the whole visual world, one file.
- `tests/test_tui.py` — headless Pilot tests (boot, tab switch, filters).

## Constraints

Stays monochrome under future edits: no `SEV` colour imports in `tui/`,
no emoji severity icons, no `border-left` accents, no metric-card grids.
Backend seam unchanged: `ScanRequest (enable_ai, max_pages)`.
