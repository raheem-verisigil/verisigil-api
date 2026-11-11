import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";

test("MCP stdio handshake and tool discovery work without API access", async (t) => {
  const child = spawn(process.execPath, ["src/server.mjs"], {
    cwd: new URL("..", import.meta.url),
    stdio: ["pipe", "pipe", "ignore"]
  });
  t.after(() => child.kill("SIGTERM"));
  let buffer = "";
  const lines = [];
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", chunk => {
    buffer += chunk;
    for (;;) {
      const index = buffer.indexOf("\n");
      if (index < 0) break;
      lines.push(buffer.slice(0, index));
      buffer = buffer.slice(index + 1);
    }
  });
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }) + "\n");
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }) + "\n");
  for (let i = 0; i < 40 && lines.length < 2; i++) await new Promise(resolve => setTimeout(resolve, 25));
  assert.equal(lines.length, 2);
  const initialized = JSON.parse(lines[0]);
  const listed = JSON.parse(lines[1]);
  assert.equal(initialized.result.serverInfo.name, "verisigil-builder-mcp-readonly");
  assert.equal(listed.result.tools.length, 4);
  assert.ok(listed.result.tools.every(tool => tool.inputSchema.additionalProperties === false));
});
