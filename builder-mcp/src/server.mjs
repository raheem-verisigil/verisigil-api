import { createInterface } from "node:readline";
import { ApiClient } from "./api-client.mjs";

const client = new ApiClient();
const tools = [
  { name: "verisigil_health", description: "Read the API health status.", inputSchema: { type: "object", properties: {}, additionalProperties: false } },
  { name: "verisigil_invariants", description: "Read the published invariant summary.", inputSchema: { type: "object", properties: {}, additionalProperties: false } },
  { name: "verisigil_named_invariants", description: "Read named invariant descriptions.", inputSchema: { type: "object", properties: {}, additionalProperties: false } },
  { name: "verisigil_conformance_vectors", description: "Read published conformance vectors.", inputSchema: { type: "object", properties: {}, additionalProperties: false } }
];
const routeByTool = {
  verisigil_health: "health",
  verisigil_invariants: "invariants",
  verisigil_named_invariants: "named_invariants",
  verisigil_conformance_vectors: "conformance_vectors"
};

function response(id, result) { return { jsonrpc: "2.0", id, result }; }
function error(id, code, message) { return { jsonrpc: "2.0", id, error: { code, message } }; }
async function handle(message) {
  if (!message || message.jsonrpc !== "2.0" || typeof message.method !== "string") {
    return message?.id === undefined ? null : error(message.id, -32600, "Invalid request");
  }
  if (message.method === "notifications/initialized" || message.method === "notifications/cancelled") return null;
  if (message.method === "initialize") {
    return response(message.id, {
      protocolVersion: "2025-03-26",
      capabilities: { tools: {} },
      serverInfo: { name: "verisigil-builder-mcp-readonly", version: "0.1.0" }
    });
  }
  if (message.method === "ping") return response(message.id, {});
  if (message.method === "tools/list") return response(message.id, { tools });
  if (message.method === "tools/call") {
    const name = message.params?.name;
    const route = routeByTool[name];
    if (!route) return error(message.id, -32602, "Unknown read-only tool");
    const args = message.params?.arguments ?? {};
    if (!args || typeof args !== "object" || Array.isArray(args) || Object.keys(args).length) {
      return error(message.id, -32602, "This tool accepts no arguments");
    }
    try {
      const data = await client.get(route);
      return response(message.id, { content: [{ type: "text", text: JSON.stringify(data) }], isError: false });
    } catch {
      return response(message.id, { content: [{ type: "text", text: "The configured API request failed." }], isError: true });
    }
  }
  return message.id === undefined ? null : error(message.id, -32601, "Method not found");
}

const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of rl) {
  if (!line.trim()) continue;
  let msg;
  try { msg = JSON.parse(line); } catch { process.stdout.write(JSON.stringify(error(null, -32700, "Parse error")) + "\n"); continue; }
  const result = await handle(msg);
  if (result) process.stdout.write(JSON.stringify(result) + "\n");
}
