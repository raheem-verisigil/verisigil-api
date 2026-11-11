import test from "node:test";
import assert from "node:assert/strict";
import { ApiClient } from "../src/api-client.mjs";

test("remote API targets are blocked by default", () => {
  assert.throws(() => new ApiClient({ baseUrl: "https://example.com" }), /Remote API targets are disabled/);
});

test("non-allowlisted routes cannot be requested", async () => {
  const client = new ApiClient();
  await assert.rejects(() => client.get("execute"), /not allowlisted/);
});

test("credentials in URL are rejected", () => {
  assert.throws(() => new ApiClient({ baseUrl: "http://user:pass@127.0.0.1:8000" }), /Invalid API base URL/);
});
