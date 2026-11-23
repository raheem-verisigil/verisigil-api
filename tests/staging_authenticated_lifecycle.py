#!/usr/bin/env python3
"""Live acceptance tests for isolated staging Passport, tenant and authority lifecycle."""
import base64, hashlib, json, os, urllib.error, urllib.parse, urllib.request, uuid
from datetime import datetime, timedelta, timezone

import rfc8785
from nacl.signing import SigningKey

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

def new_agent_key():
    signing_key=SigningKey.generate()
    public_raw=bytes(signing_key.verify_key)
    return signing_key,base64.b64encode(public_raw).decode("ascii"),hashlib.sha256(public_raw).hexdigest()

def sign_payload(signing_key,payload):
    signature=signing_key.sign(rfc8785.dumps(payload)).signature
    return "Ed25519:"+base64.b64encode(signature).decode("ascii")

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

    ci/include-main-py-in-passport-gate-20261123
status,_=call(BASE+"/v1/agent-identity/api-keys","POST",owner_tenant,{"name":"invalid-scope","scopes":["*"],"expires_in_days":1})
assert status==422,f"unsupported API-key scope was not rejected: HTTP {status}"
print("PASS: unsupported API-key scopes rejected")

status,body=call(BASE+f"/v1/agent-identity/api-keys/{key_id}/revoke","POST",owner_tenant)

status,_=call(BASE+"/v1/agent-identity/api-keys","POST",owner,{"name":"invalid-scope","scopes":["*"],"expires_in_days":1})
assert status==422,f"unsupported API-key scope was not rejected: HTTP {status}"
print("PASS: unsupported API-key scopes rejected")

status,body=call(BASE+f"/v1/agent-identity/api-keys/{key_id}/revoke","POST",owner)
 main
assert status==200 and isinstance(body,dict) and body.get("revoked") is True,f"API-key revoke failed: HTTP {status}"
status,_=call(BASE+"/v1/agent-identity/agents",headers={"x-api-key":key})
assert status==401,f"revoked API key still accepted: HTTP {status}"
print("PASS: revoked tenant API key rejected")

created_agent_ids=[]
def register_agent(label,capabilities):
    signing_key,public_key,fingerprint=new_agent_key()
    status,challenge=call(BASE+"/v1/agent-identity/challenges","POST",owner_tenant,{"purpose":"REGISTER_AGENT","public_key":public_key})
    assert status==200 and isinstance(challenge,dict) and challenge.get("sign_this_exact_object"),f"{label} registration challenge failed: HTTP {status}"
    request={"agent_name":label+"-"+uuid.uuid4().hex[:8],"public_key":public_key,"capabilities":capabilities,"expires_in_days":30,"challenge_id":challenge["challenge_id"],"proof_of_possession":sign_payload(signing_key,challenge["sign_this_exact_object"])}
    status,created=call(BASE+"/v1/agent-identity/agents","POST",owner_tenant,request)
    assert status==200 and isinstance(created,dict),f"{label} registration failed: HTTP {status}"
    agent=created.get("agent") or {}; agent_id=agent.get("agent_id")
    assert agent_id and created.get("proof_of_possession")=="VERIFIED","agent registration did not verify proof of possession"
    assert (created.get("key") or {}).get("key_id")==fingerprint,"registered key fingerprint mismatch"
    created_agent_ids.append(agent_id)
    status,detail=call(BASE+f"/v1/agent-identity/agents/{agent_id}",headers=owner_tenant)
    assert status==200 and detail.get("passport_signature_valid") is True and detail.get("passport_status")=="VALID","issued passport signature or status invalid"
    print(f"PASS: {label} Ed25519 proof-of-possession and signed passport")
    replay_status,_=call(BASE+"/v1/agent-identity/agents","POST",owner_tenant,request)
    assert replay_status==409,f"consumed {label} registration challenge replay was not rejected: HTTP {replay_status}"
    print(f"PASS: {label} registration challenge is single-use")
    return {"signing_key":signing_key,"public_key":public_key,"key_id":fingerprint,"agent_id":agent_id}

def rotate_agent_key(agent):
 hardening/verisigil-production-readiness-20261123
    old_signing_key=agent["signing_key"]; old_key_id=agent["key_id"]
  
     main
    new_signing_key,new_public_key,new_fingerprint=new_agent_key()
    status,challenge=call(BASE+"/v1/agent-identity/challenges","POST",owner_tenant,{"purpose":"ROTATE_KEY","agent_id":agent["agent_id"],"public_key":new_public_key})
    assert status==200 and isinstance(challenge,dict) and challenge.get("sign_this_exact_object"),f"key-rotation challenge failed: HTTP {status}"
    request={"public_key":new_public_key,"challenge_id":challenge["challenge_id"],"proof_of_possession":sign_payload(new_signing_key,challenge["sign_this_exact_object"]),"replace_existing":True}
    status,result=call(BASE+f"/v1/agent-identity/agents/{agent['agent_id']}/keys","POST",owner_tenant,request)
    assert status==200 and isinstance(result,dict) and result.get("previous_keys")=="ROTATED",f"agent key rotation failed: HTTP {status}"
    assert (result.get("passport") or {}).get("claims",{}).get("passport_version")==2,"passport version did not advance on rotation"
    status,detail=call(BASE+f"/v1/agent-identity/agents/{agent['agent_id']}",headers=owner_tenant)
    keys=detail.get("keys",[]) if isinstance(detail,dict) else []
    old=next((item for item in keys if item.get("key_id")==agent["key_id"]),{})
    new=next((item for item in keys if item.get("key_id")==new_fingerprint),{})
    assert status==200 and detail.get("passport_signature_valid") is True and old.get("status")=="ROTATED" and new.get("status")=="ACTIVE","rotated key states or updated passport are invalid"
    agent.update({"signing_key":new_signing_key,"public_key":new_public_key,"key_id":new_fingerprint})
    print("PASS: proof-bound Ed25519 key rotation and passport versioning")
    hardening/verisigil-production-readiness-20261123
    replay_status,_=call(BASE+f"/v1/agent-identity/agents/{agent['agent_id']}/keys","POST",owner_tenant,request)
    assert replay_status==409,f"consumed key-rotation challenge replay was not rejected: HTTP {replay_status}"
    old_payload={"agent_id":agent["agent_id"],"key_id":old_key_id,"action":"payments.read","parameters":{},"delegation_id":None}
    old_request={"agent_id":agent["agent_id"],"key_id":old_key_id,"action":"payments.read","parameters":{},"agent_signature":sign_payload(old_signing_key,old_payload)}
    old_status,old_decision=call(BASE+"/v1/runtime/authority/evaluate","POST",owner_tenant,old_request)
    assert old_status==200 and old_decision.get("decision")=="REFUSED" and "AGENT_KEY_REVOKED_OR_INACTIVE" in old_decision.get("reasons",[]),"rotated old key retained runtime authority"
    print("PASS: rotated key cannot authorize new runtime actions")

     main

def evaluate(agent,delegation_id,parameters):
    action="payments.approve"
    action_payload={"agent_id":agent["agent_id"],"key_id":agent["key_id"],"action":action,"parameters":parameters,"delegation_id":delegation_id}
    request={"agent_id":agent["agent_id"],"key_id":agent["key_id"],"action":action,"parameters":parameters,"delegation_id":delegation_id,"agent_signature":sign_payload(agent["signing_key"],action_payload),"ttl_seconds":60}
    status,result=call(BASE+"/v1/runtime/authority/evaluate","POST",owner_tenant,request)
    assert status==200 and isinstance(result,dict) and result.get("decision")=="AUTHORIZED" and result.get("execution_authorized") is False and result.get("actuator_invoked") is False,f"runtime authority evaluation failed: HTTP {status}"
    print("PASS: delegated action evaluated and signed without invoking actuator")
    return result,{"commitment_id":result["commitment_id"],"action":action,"parameters":parameters,"agent_signature":sign_payload(agent["signing_key"],{"commitment_id":result["commitment_id"],"action_digest":result["action_digest"],"agent_id":agent["agent_id"],"key_id":agent["key_id"]})}

def consume(agent,consume_request,expected_status=200):
    status,result=call(BASE+"/v1/runtime/authority/consume","POST",owner_tenant,consume_request)
    assert status==expected_status,f"authority consume expected HTTP {expected_status}, got {status}"
    return result

def revoke_agent(agent_id):
    status,result=call(BASE+f"/v1/agent-identity/agents/{agent_id}/revoke","POST",owner_tenant)
    assert status==200 and isinstance(result,dict) and result.get("status")=="REVOKED",f"agent revocation failed: HTTP {status}"
    return result

try:
    grantor=register_agent("staging-grantor",["payments.approve","payments.read"])
    grantee=register_agent("staging-grantee",["payments.read"])
    rotate_agent_key(grantor)

    expiry=(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()
     hardening/verisigil-production-readiness-20261123
    status,_=call(BASE+"/v1/agent-identity/delegations","POST",owner_tenant,{"grantor_agent_id":grantor["agent_id"],"grantee_agent_id":grantee["agent_id"],"scopes":["payments.admin"],"expires_at":expiry})
    assert status==403,f"delegation exceeded grantor capabilities: HTTP {status}"
    print("PASS: delegation cannot exceed grantor capabilities")
    status,delegation=call(BASE+"/v1/agent-identity/delegations","POST",owner_tenant,{"grantor_agent_id":grantor["agent_id"],"grantee_agent_id":grantee["agent_id"],"scopes":["payments.approve"],"expires_at":expiry})
    assert status==200 and isinstance(delegation,dict) and delegation.get("status")=="ACTIVE",f"bounded delegation creation failed: HTTP {status}"
    delegation_id=delegation["delegation_id"]

    status,delegation=call(BASE+"/v1/agent-identity/delegations","POST",owner_tenant,{"grantor_agent_id":grantor["agent_id"],"grantee_agent_id":grantee["agent_id"],"scopes":["payments.approve"],"expires_at":expiry})
    assert status==200 and isinstance(delegation,dict) and delegation.get("status")=="ACTIVE",f"bounded delegation creation failed: HTTP {status}"
    delegation_id=delegation["delegation_id"]
    print("PASS: delegation cannot exceed grantor capabilities")

     main
    parameters={"invoice_id":"INV-STAGING-001","amount_minor":12500}
    decision,consume_request=evaluate(grantee,delegation_id,parameters)
    status,receipt=call(BASE+f"/v1/runtime/authority/receipts/{decision['commitment_id']}",headers=owner_tenant)
    assert status==200 and receipt.get("issuer_signature_valid") is True and receipt.get("consumable") is True,"authority decision receipt is invalid or not consumable"
    consumed=consume(grantee,consume_request)
    assert consumed.get("execution_authorized") is True and consumed.get("actuator_invoked") is False,"consume did not return a non-actuating authorization receipt"
    status,receipt=call(BASE+f"/v1/runtime/authority/receipts/{decision['commitment_id']}",headers=owner_tenant)
    assert status==200 and receipt.get("issuer_signature_valid") is True and receipt.get("consumed") is True and receipt.get("consumable") is False,"consumption receipt was not durably verified"
    print("PASS: authority commitment atomically consumed once with verifiable receipt")
    replay_status,_=call(BASE+"/v1/runtime/authority/consume","POST",owner_tenant,consume_request)
    assert replay_status==409,f"authority commitment replay was not rejected: HTTP {replay_status}"
    print("PASS: authority commitment cannot be consumed twice")

    parameters2={"invoice_id":"INV-STAGING-002","amount_minor":25000}
    decision2,consume_request2=evaluate(grantee,delegation_id,parameters2)
    status,revoked=call(BASE+f"/v1/agent-identity/delegations/{delegation_id}/revoke","POST",owner_tenant)
    assert status==200 and isinstance(revoked,dict) and revoked.get("status")=="REVOKED","delegation revocation failed"
    status,receipt2=call(BASE+f"/v1/runtime/authority/receipts/{decision2['commitment_id']}",headers=owner_tenant)
    reasons=receipt2.get("current_authority_reasons",[]) if isinstance(receipt2,dict) else []
    assert status==200 and receipt2.get("consumable") is False and "DELEGATION_MISSING_OR_REVOKED" in reasons,"revoked delegation did not invalidate pending authority"
    consume(grantee,consume_request2,expected_status=403)
    print("PASS: delegation revocation blocks pending authority at consume boundary")

    grantee_revoke=revoke_agent(grantee["agent_id"])
    assert grantee_revoke.get("revoked_keys",0)>=1,"agent revocation did not revoke its active key"
    grantor_revoke=revoke_agent(grantor["agent_id"])
    assert grantor_revoke.get("revoked_keys",0)>=1,"grantor revocation did not revoke its active rotated key"
    print("PASS: agent revocation cascades to active cryptographic keys")
finally:
    # Best-effort cleanup also runs when an earlier assertion fails.
    for agent_id in reversed(created_agent_ids):
        try:
            call(BASE+f"/v1/agent-identity/agents/{agent_id}/revoke","POST",owner_tenant)
        except Exception:
            pass

print("PASS: mandatory authenticated Passport and runtime-authority acceptance")
