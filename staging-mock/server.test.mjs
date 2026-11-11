import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";

test("mock API exposes only the documented read-only fixture routes", async (t) => {
  const port = 18080 + Math.floor(Math.random() * 1000);
  const child = spawn(process.execPath, ["server.mjs"], {
    cwd: new URL(".", import.meta.url),
    env: { ...process.env, PORT: String(port) },
    stdio: "ignore"
  });
  t.after(() => child.kill("SIGTERM"));
  const base = `http://127.0.0.1:${port}`;
  let ready = false;
  for (let i = 0; i < 40; i++) {
    try {
      const r = await fetch(`${base}/health`);
      if (r.ok) { ready = true; break; }
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  assert.equal(ready, true, "server should become healthy");
  for (const path of ["/health", "/v1/invariants", "/v1/invariants/named", "/v1/conformance/vectors"]) {
    const response = await fetch(base + path);
    assert.equal(response.status, 200, path);
    assert.equal(response.headers.get("cache-control"), "no-store");
  }
  assert.equal((await fetch(base + "/admin")).status, 404);
  assert.equal((await fetch(base + "/v1/execute")).status, 404);
  assert.equal((await fetch(base + "/health", { method: "POST" })).status, 405);
  assert.equal((await fetch(base + "/health?x=1")).status, 400);
});
