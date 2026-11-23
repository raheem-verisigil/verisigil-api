#!/usr/bin/env python3
"""Live acceptance tests for isolated staging tenant onboarding and API-key lifecycle."""
import base64, json, os, urllib.error, urllib.parse, urllib.request, uuid

BASE=os.environ.get("VERISIGIL_STAGING_BASE_URL","").rstrip("/")
SUPA=os.environ.get("VERISIGIL_STAGING_SUPABASE_URL","").rstrip("/")
ANON=os.environ.get("VERISIGIL_STAGING_SUPABASE_ANON_KEY","")
OWNER=(os.environ.get("VERISIGIL_STAGING_TEST_OWNER_EMAIL",""),os.environ.get("VERISIGIL_STAGING_TEST_OWNER_PASSWORD",""))
OTHER=(os.environ.get("VERISIGIL_STAGING_TEST_OTHER_EMAIL",""),os.environ.get("VERISIGIL_STAGING_TEST_OTHER_PASSWORD",""))
required={"VERISIGIL_STAGING_BASE_URL":BASE,"VERISIGIL_STAGING_SUPABASE_URL":SUPA,"VERISIGIL_STAGING_SUPABASE_ANON_KEY":ANON,"VERISIGIL_STAGING_TEST_OWNER_EMAIL":OWNER[0],"VERISIGIL_STAGING_TEST_OWNER_PASSWORD":OWNER[1],"VERISIGIL_STAGING_TEST_OTHER_EMAIL":OTHER[0],"VERISIGIL_STAGING_TEST_OTHER_PASSWORD":OTHER[1]}
missing=[k for k,v in required.items() if not v]
if missing: raise SystemExit("Missing required isolated-staging secrets: "+", ".join(missing))
host=urllib.parse.urlparse(BASE).hostname or ""
if not BASE.startswith("https://") or not SUPA.startswith("https://") or not host.endswith(".up.railway.app") or "production" in host.lower():
    raise SystemExit("Refusing non-isolated or non-HTTPS staging target")
if OWNER[0].lower()==OTHER[0].lower(): raise SystemExit("Two distinct staging test users are required")

def call(url,method="GET",headers=None,payload=None):
    data=None if payload is None else json.dumps(payload).encode()
    req=urllib.request.Request(url,data=data,method=method,headers={"Accept":"application/json",**({"Content-Type":"application/json"} if data is not None else {}),**(headers or {})})
    try:
        with urllib.request.urlopen(req,timeout=25) as r:
            raw=r.read(); return r.status,json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        raw=e.read()
        try: body=json.loads(raw) if raw else None
        except Exception: body=None
        return e.code,body

def login(pair):
    status,body=call(SUPA+"/auth/v1/token?grant_type=password","POST",{"apikey":ANON},{"email":pair[0],"password":pair[1]})
    assert status==200 and isinstance(body,dict) and body.get("access_token"),f"staging auth login failed: HTTP {status}"
    return {"Authorization":"Bearer "+body["access_token"]}

owner=login(OWNER); other=login(OTHER)
status,body=call(BASE+"/v1/agent-identity/tenants",headers=other)
assert status==200 and isinstance(body,dict) and body.get("tenants")==[],f"unassigned user tenant list unexpected: HTTP {status}"
print("PASS: unrelated authenticated user cannot enumerate owner's tenant")

name="staging-acceptance-"+uuid.uuid4().hex[:12]
status,body=call(BASE+"/v1/agent-identity/tenants","POST",owner,{"tenant_name":name})
assert status==200 and isinstance(body,dict),f"tenant onboarding failed: HTTP {status}"
tenant=body.get("tenant") or {}; membership=body.get("membership") or {}; org=tenant.get("org_id")
assert body.get("onboarding")=="TENANT_OWNER_CREATED" and org,"tenant creation not confirmed"
assert membership.get("org_id")==org and membership.get("role")=="owner","owner membership missing"
owner_tenant={**owner,"x-org-id":org}
print("PASS: authenticated tenant and owner membership created")

status,body=call(BASE+"/v1/agent-identity/tenants",headers=owner)
rows=body.get("tenants",[]) if isinstance(body,dict) else []
assert status==200 and any((x.get("tenant") or {}).get("org_id")==org for x in rows),"tenant not visible on read-after-write"
print("PASS: tenant persists across authenticated read")

status,_=call(BASE+"/v1/agent-identity/agents",headers={**other,"x-org-id":org})
assert status==403,f"cross-tenant membership selection not denied: HTTP {status}"
print("PASS: cross-tenant selection denied")

status,body=call(BASE+"/v1/agent-identity/api-keys","POST",owner_tenant,{"name":"staging-"+uuid.uuid4().hex[:8],"scopes":["agents:read"],"expires_in_days":1})
assert status==200 and isinstance(body,dict) and body.get("api_key") and body.get("key_id"),f"API-key issue failed: HTTP {status}"
key=body["api_key"]; key_id=body["key_id"]
status,_=call(BASE+"/v1/agent-identity/agents",headers={"x-api-key":key})
assert status==200,f"scoped API key failed: HTTP {status}"
print("PASS: scoped tenant API key grants read access")

# A read-only key must not create agent challenges or manage other API keys.
limited={"x-api-key":key}
status,_=call(BASE+"/v1/agent-identity/challenges","POST",limited,{"purpose":"REGISTER_AGENT","public_key":base64.b64encode(bytes(32)).decode("ascii")})
assert status==403,f"read-only key unexpectedly created an agent challenge: HTTP {status}"
print("PASS: agents:read key cannot perform agents:write operation")

status,_=call(BASE+"/v1/agent-identity/api-keys","POST",limited,{"name":"forbidden-escalation","scopes":["agents:read"],"expires_in_days":1})
assert status==403,f"tenant API key unexpectedly created another API key: HTTP {status}"
print("PASS: tenant API key cannot escalate or mint credentials")

status,_=call(BASE+"/v1/agent-identity/api-keys","POST",owner_tenant,{"name":"invalid-scope","scopes":["*"],"expires_in_days":1})
assert status==422,f"unsupported API-key scope was not rejected: HTTP {status}"
print("PASS: unsupported API-key scopes rejected")

status,body=call(BASE+f"/v1/agent-identity/api-keys/{key_id}/revoke","POST",owner_tenant)
assert status==200 and isinstance(body,dict) and body.get("revoked") is True,f"API-key revoke failed: HTTP {status}"
status,_=call(BASE+"/v1/agent-identity/agents",headers={"x-api-key":key})
assert status==401,f"revoked API key still accepted: HTTP {status}"
print("PASS: revoked API key rejected")
print("PASS: mandatory authenticated staging lifecycle and negative-scope gates")
