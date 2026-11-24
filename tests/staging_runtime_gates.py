#!/usr/bin/env python3
"""Read-only live staging gates: health, OpenAPI and unauthenticated denial."""
import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ["VERISIGIL_STAGING_BASE_URL"].rstrip("/")

def request(path):
    req = urllib.request.Request(BASE + path, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()

status, body = request("/health")
assert status == 200, f"health returned HTTP {status}: {body[:300]!r}"
health = json.loads(body)
assert isinstance(health, dict), "health response must be a JSON object"
print("PASS: live health endpoint returned HTTP 200")

status, body = request("/openapi.json")
assert status == 200, f"OpenAPI returned HTTP {status}: {body[:300]!r}"
schema = json.loads(body)
paths = schema.get("paths", {})
required = {
    "/v1/agent-identity/tenants",
    "/v1/agent-identity/challenges",
    "/v1/agent-identity/agents",
    "/v1/runtime/authority/evaluate",
    "/v1/runtime/authority/consume",
}
missing = sorted(required - set(paths))
assert not missing, f"Passport/authority routes missing from deployed OpenAPI: {missing}"
schemes = schema.get("components", {}).get("securitySchemes", {})
assert "SupabaseBearer" in schemes, "Supabase bearer security scheme missing"
print("PASS: live OpenAPI exposes Passport, challenge, runtime authority and Supabase Auth")

for path in ("/v1/agent-identity/tenants", "/v1/agent-identity/agents"):
    status, body = request(path)
    assert status == 401, f"unauthenticated {path} returned HTTP {status}, expected 401: {body[:300]!r}"
    print(f"PASS: unauthenticated request denied with HTTP 401: {path}")

print("PASS: all read-only live staging runtime gates")
