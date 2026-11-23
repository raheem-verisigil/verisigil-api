#!/usr/bin/env python3
"""Mandatory live staging tests for authenticated tenant lifecycle and isolation.

Uses two pre-provisioned, non-production Supabase Auth test users. Creates one
uniquely named tenant and one short-lived tenant API key, then revokes the key.
No production host is accepted. Test users must belong only to isolated staging.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

BASE = os.environ.get("VERISIGIL_STAGING_BASE_URL", "").rstrip("/")
SUPABASE_URL = os.environ.get("VERISIGIL_STAGING_SUPABASE_URL", "").rstrip("/")
ANON = os.environ.get("VERISIGIL_STAGING_SUPABASE_ANON_KEY", "")
OWNER_EMAIL = os.environ.get("VERISIGIL_STAGING_TEST_OWNER_EMAIL", "")
OWNER_PASSWORD = os.environ.get("VERISIGIL_STAGING_TEST_OWNER_PASSWORD", "")
OTHER_EMAIL = os.environ.get("VERISIGIL_STAGING_TEST_OTHER_EMAIL", "")
OTHER_PASSWORD = os.environ.get("VERISIGIL_STAGING_TEST_OTHER_PASSWORD", "")

required = {
    "VERISIGIL_STAGING_BASE_URL": BASE,
    "VERISIGIL_STAGING_SUPABASE_URL": SUPABASE_URL,
    "VERISIGIL_STAGING_SUPABASE_ANON_KEY": ANON,
    "VERISIGIL_STAGING_TEST_OWNER_EMAIL": OWNER_EMAIL,
    "VERISIGIL_STAGING_TEST_OWNER_PASSWORD": OWNER_PASSWORD,
    "VERISIGIL_STAGING_TEST_OTHER_EMAIL": OTHER_EMAIL,
    "VERISIGIL_STAGING_TEST_OTHER_PASSWORD": OTHER_PASSWORD,
}
missing = [name for name, value in required.items() if not value]
if missing:
    raise SystemExit("FAIL: required staging test configuration/secrets missing: " + ", ".join(missing))
if not BASE.startswith("https://") or not SUPABASE_URL.startswith("https://"):
    raise SystemExit("FAIL: staging URLs must use HTTPS")
host = urllib.parse.urlparse(BASE).hostname or ""
if "production" in host.lower() or not host.endswith(".up.railway.app"):
    raise SystemExit("FAIL: live lifecycle tests are restricted to the isolated Railway staging host")
if OWNER_EMAIL.lower() == OTHER_EMAIL.lower():
    raise SystemExit("FAIL: isolation test requires two distinct staging users")

def request(url, method="GET", headers=None, payload=None):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Accept": "application/json",
        **({"Content-Type": "application/json"} if data is not None else {}),
        **(headers or {}),
    })
    try:
        with urllib.request.urlopen(req, timeout=25) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            body = json.loads(raw) if raw else None
        except Exception:
            body = raw[:300].decode("utf-8", "replace")
        return exc.code, body

def login(email, password):
    status, body = request(
        SUPABASE_URL + "/auth/v1/token?grant_type=password",
        "POST", {"apikey": ANON}, {"email": email, "password": password}
    )
    if status != 200 or not isinstance(body, dict) or not body.get("access_token"):
        raise AssertionError(f"Supabase staging test-user login failed: HTTP {status}")
    return body["access_token"]

owner_token = login(OWNER_EMAIL, OWNER_PASSWORD)
other_token = login(OTHER_EMAIL, OTHER_PASSWORD)
owner_auth = {"Authorization": "Bearer " + owner_token}
other_auth = {"Authorization": "Bearer " + other_token}

# The second identity must not inherit or enumerate the first user's tenant.
status, body = request(BASE + "/v1/agent-identity/tenants", headers=other_auth)
assert status == 200 and isinstance(body, dict) and body.get("tenants") == [], (
    f"unassigned test user should see an empty tenant list; got HTTP {status}"
)
print("PASS: second authenticated user cannot enumerate the owner's tenant")

# Create tenant through verified Supabase Auth; server must atomically create owner membership.
tenant_name = "staging-acceptance-" + uuid.uuid4().hex[:12]
status, body = request(BASE + "/v1/agent-identity/tenants", "POST", owner_auth, {"tenant_name": tenant_name})
assert status == 200 and isinstance(body, dict), f"tenant creation failed: HTTP {status}"
tenant = body.get("tenant") or {}
membership = body.get("membership") or {}
org_id = tenant.get("org_id")
assert body.get("onboarding") == "TENANT_OWNER_CREATED" and org_id, "tenant response lacks committed tenant identity"
assert membership.get("org_id") == org_id and membership.get("role") == "owner", "owner membership was not returned for created tenant"
print("PASS: authenticated tenant and owner membership created")

# Read-after-write through the authenticated API proves durable visibility, not only response construction.
status, body = request(BASE + "/v1/agent-identity/tenants", headers=owner_auth)
visible = body.get("tenants", []) if isinstance(body, dict) else []
assert status == 200 and any((item.get("tenant") or {}).get("org_id") == org_id for item in visible), (
    f"created tenant not visible on subsequent authenticated read: HTTP {status}"
)
print("PASS: tenant persists and is visible on a subsequent authenticated request")

# An unrelated authenticated user cannot select the owner's tenant by supplying its org id.
status, _ = request(BASE + "/v1/agent-identity/agents", headers={
    **other_auth, "x-org-id": org_id,
})
assert status == 403, f"cross-tenant membership selection returned HTTP {status}, expected 403"
print("PASS: cross-tenant membership selection is rejected")

# Issue a restricted tenant API key, prove it works, revoke it, and prove revocation takes effect.
status, body = request(BASE + "/v1/agent-identity/api-keys", "POST", owner_auth, {
    "name": "staging-acceptance-" + uuid.uuid4().hex[:8],
    "scopes": ["agents:read"],
    "expires_in_days": 1,
})
assert status == 200 and isinstance(body, dict) and body.get("api_key") and body.get("key_id"), (
    f"tenant API-key creation failed: HTTP {status}"
)
api_key = body["api_key"]
key_id = body["key_id"]
status, _ = request(BASE + "/v1/agent-identity/agents", headers={"x-api-key": api_key})
assert status == 200, f"new tenant API key could not read its tenant: HTTP {status}"
print("PASS: tenant-scoped API key grants its declared read scope")

status, body = request(BASE + f"/v1/agent-identity/api-keys/{key_id}/revoke", "POST", owner_auth)
assert status == 200 and isinstance(body, dict) and body.get("revoked") is True, (
    f"tenant API-key revocation failed: HTTP {status}"
)
status, _ = request(BASE + "/v1/agent-identity/agents", headers={"x-api-key": api_key})
assert status == 401, f"revoked tenant API key remained usable: HTTP {status}"
print("PASS: revoked tenant API key is rejected")

print("PASS: mandatory authenticated staging lifecycle and isolation gates")
