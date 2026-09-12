// api/health.ts
async function GET() {
  return {
    api: process.env.WEBVAPT_API_URL || "http://127.0.0.1:8000/api/v1",
    hasKey: Boolean(process.env.WEBVAPT_API_KEY)
  };
}
export {
  GET
};
