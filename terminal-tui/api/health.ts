// GET /api/health — local TUI helper (not the Python engine).
// Reports which Python API URL this TUI talks to.
export async function GET() {
  return {
    api: process.env.WEBVAPT_API_URL || "http://127.0.0.1:8000/api/v1",
    hasKey: Boolean(process.env.WEBVAPT_API_KEY),
  };
}
