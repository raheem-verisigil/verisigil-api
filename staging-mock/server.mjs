import http from "node:http";

const PORT = Number(process.env.PORT || 8080);
const HOST = "0.0.0.0";
const fixtures = Object.freeze({
  invariants: {
    environment: "isolated-staging",
    mode: "read-only-fixture",
    items: [
      { id: "fixture-001", name: "receipt-integrity", status: "fixture-only" },
      { id: "fixture-002", name: "parameter-binding", status: "fixture-only" }
    ]
  },
  named: {
    environment: "isolated-staging",
    items: [
      { name: "receipt-integrity", description: "Synthetic fixture; not a production claim." },
      { name: "parameter-binding", description: "Synthetic fixture; not a production claim." }
    ]
  },
  vectors: {
    environment: "isolated-staging",
    vectors: [
      { id: "vector-001", input: { amount: 100, currency: "TEST" }, expected: "fixture-accepted" },
      { id: "vector-002", input: { amount: -1, currency: "TEST" }, expected: "fixture-rejected" }
    ]
  }
});

function send(res, status, value) {
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff"
  });
  res.end(JSON.stringify(value));
}

const server = http.createServer((req, res) => {
  if (req.method !== "GET") {
    res.setHeader("allow", "GET");
    return send(res, 405, { error: "method_not_allowed" });
  }
  const url = new URL(req.url || "/", "http://localhost");
  if (url.search || url.hash) return send(res, 400, { error: "query_not_supported" });
  if (url.pathname === "/health") {
    return send(res, 200, { ok: true, service: "verisigil-isolated-staging-mock", environment: "isolated-staging", fixture_only: true });
  }
  if (url.pathname === "/v1/invariants") return send(res, 200, fixtures.invariants);
  if (url.pathname === "/v1/invariants/named") return send(res, 200, fixtures.named);
  if (url.pathname === "/v1/conformance/vectors") return send(res, 200, fixtures.vectors);
  return send(res, 404, { error: "not_found" });
});

server.listen(PORT, HOST, () => {
  process.stdout.write(`isolated staging mock listening on ${HOST}:${PORT}\n`);
});

function shutdown() {
  server.close(() => process.exit(0));
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
