import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { TUIEmulator } from "terminaltui/emulator";

describe("webvapt-tui boot", () => {
  it("boots and shows the incident-report menu", async () => {
    const app = await TUIEmulator.launch({ command: "node", args: ["dist/cli.js"], timeout: 30000 });
    try {
      await app.waitForText("WEBVAPT", { timeout: 25000 });
      const snap = app.snapshot().text;
      assert.match(snap, /WEBVAPT/);
    } finally {
      await app.close();
    }
  });
});
