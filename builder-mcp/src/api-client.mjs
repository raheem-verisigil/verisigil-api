const ROUTES = Object.freeze({
  health: "/health",
  invariants: "/v1/invariants",
  named_invariants: "/v1/invariants/named",
  conformance_vectors: "/v1/conformance/vectors"
});

function assertAllowedBase(raw) {
  const url = new URL(raw);
  const loopback = ["localhost", "127.0.0.1", "::1"].includes(url.hostname);
  if (!loopback && process.env.VERISIGIL_ALLOW_REMOTE !== "true") {
    throw new Error("Remote API targets are disabled");
  }
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Unsupported API protocol");
  if (url.username || url.password || url.search || url.hash) throw new Error("Invalid API base URL");
  return url;
}

export class ApiClient {
  constructor({ baseUrl = process.env.VERISIGIL_API_URL || "http://127.0.0.1:8000", apiKey = process.env.VERISIGIL_API_KEY, timeoutMs = 5000 } = {}) {
    this.base = assertAllowedBase(baseUrl);
    this.apiKey = apiKey;
    this.timeoutMs = timeoutMs;
  }

  async get(name) {
    const path = ROUTES[name];
    if (!path) throw new Error("Route is not allowlisted");
    const target = new URL(path, this.base);
    if (target.origin !== this.base.origin) throw new Error("Cross-origin request blocked");
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const headers = { accept: "application/json" };
      if (this.apiKey) headers["x-api-key"] = this.apiKey;
      const response = await fetch(target, { method: "GET", headers, signal: controller.signal, redirect: "error" });
      if (!response.ok) throw new Error(`API request failed with status ${response.status}`);
      const type = response.headers.get("content-type") || "";
      if (!type.toLowerCase().includes("application/json")) throw new Error("API returned a non-JSON response");
      return await response.json();
    } catch (error) {
      if (error.name === "AbortError") throw new Error("API request timed out");
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }
}
