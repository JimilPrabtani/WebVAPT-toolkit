# webvapt-tui — WebVAPT terminal UI (terminaltui)

Thin TypeScript client over the Python FastAPI scan engine. Black ground,
white ink; severity as ASCII text (`[!!]/[!]/[*]/[.]/[i]`), never hue.

## Split URLs

- **API** (Python): `http://127.0.0.1:8000/api/v1` — `uvicorn main:app --port 8000`
  from the project root.
- **TUI** (this app): runs separately via `npm run dev`. Point it at the API with:

```bash
WEBVAPT_API_URL=http://127.0.0.1:8000/api/v1
WEBVAPT_API_KEY=...   # must match API_KEY in the root .env (omit when unset)
```

No config needed for local runs: when `WEBVAPT_API_KEY` is not exported,
the TUI falls back to `terminal-tui/.env`, then to `API_KEY` in the
project-root `.env`. 401 responses name the fix on-screen.

See `.env.example`. The Node side never implements scanning — it calls
`POST /scan`, polls `GET /scan/{id}/status`, and reads `GET /scan/{id}`,
`GET /history`, `GET /stats`.

## Pages

| File | Screen |
|---|---|
| `pages/home.ts` | Landing menu |
| `pages/scan.ts` | New scan form (target + AI toggle + pages 1–50) |
| `pages/scan/[id].ts` | Live status poll + full results |
| `pages/results.ts` | Latest scan summary + findings |
| `pages/history.ts` | Past scans (auto-refresh) |
| `pages/help.ts` | Workflow + legal |

Shared client + incident-report formatting lives in `lib/api.ts`
(port of the old `tui/backend.py` helpers).

## Commands

```bash
npm install
npm run dev        # interactive preview
npm run build      # bundle to dist/cli.js (shipped via `npx webvapt-tui`)
npm test           # node:test — lib unit + TUIEmulator boot (7 tests)
npm run typecheck
```

`terminaltui serve --port 2222` (npm run serve) hosts the TUI over SSH.
