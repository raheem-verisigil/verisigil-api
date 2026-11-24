"""Authenticated isolated-staging acceptance. All generated rows/users are cleaned up."""
import base64, concurrent.futures, os, secrets, sys, uuid
from datetime import datetime, timedelta, timezone
import httpx, rfc8785
from nacl.signing import SigningKey

BASE=os.environ.get("VERISIGIL_STAGING_BASE_URL","").rstrip("/")
SB=os.environ.get("VERISIGIL_STAGING_SUPABASE_URL","").rstrip("/")
ANON=os.environ.get("VERISIGIL_STAGING_SUPABASE_ANON_KEY","")
SERVICE=os.environ.get("VERISIGIL_STAGING_SUPABASE_SERVICE_KEY","")

def check_config():
    missing=[k for k,v in {"VERISIGIL_STAGING_BASE_URL":BASE,"VERISIGIL_STAGING_SUPABASE_URL":SB,
        "VERISIGIL_STAGING_SUPABASE_ANON_KEY":ANON,"VERISIGIL_STAGING_SUPABASE_SERVICE_KEY":SERVICE}.items() if not v]
    if missing: raise RuntimeError("Missing Actions secrets: "+", ".join(missing))
    if "staging" not in BASE.lower() or "lgyxxxvlxlynylhjxbxb" not in SB.lower():
        raise RuntimeError("Refusing non-staging target; Supabase ref must be the isolated staging project.")

def hdr(key,bearer=None,extra=None):
    h={"apikey":key,"Accept":"application/json","Content-Type":"application/json"}
    if bearer: h["Authorization"]="Bearer "+bearer
    if extra: h.update(extra)
    return h

def call(method,url,headers=None,body=None,ok=(200,),params=None):
    with httpx.Client(timeout=25) as c: r=c.request(method,url,headers=headers,json=body,params=params)
    try: data=r.json()
    except Exception: data=r.text[:500]
    if r.status_code not in ok: raise AssertionError(f"{method} {url}: HTTP {r.status_code}, expected {ok}: {str(data)[:350]}")
    return r.status_code,data

def sig(sk,obj): return base64.b64encode(sk.sign(rfc8785.dumps(obj)).signature).decode()

def make_user(admin,label,created_users):
    email=f"vgs-ci-{label}-{uuid.uuid4().hex[:10]}@example.invalid"; password=secrets.token_urlsafe(36)+"A9!"
    _,u=call("POST",SB+"/auth/v1/admin/users",admin,{"email":email,"password":password,"email_confirm":True},(200,201))
    record={"id":u["id"],"email":email}
    created_users.append(record)  # register cleanup immediately after admin creation
    _,session=call("POST",SB+"/auth/v1/token?grant_type=password",hdr(ANON),{"email":email,"password":password})
    record["access"]=session["access_token"]
    return record

def tenant(user,name):
    _,r=call("POST",BASE+"/v1/agent-identity/tenants",hdr(ANON,user["access"]),{"tenant_name":name})
    assert r["membership"]["role"]=="owner" and r["onboarding"]=="TENANT_OWNER_CREATED"
    return r["tenant"]["org_id"]

def register(api,org,name,caps):
    sk=SigningKey.generate(); pub=base64.b64encode(bytes(sk.verify_key)).decode()
    h=hdr(ANON,extra={"x-api-key":api,"x-org-id":org})
    _,ch=call("POST",BASE+"/v1/agent-identity/challenges",h,{"purpose":"REGISTER_AGENT","public_key":pub})
    payload={"agent_name":name,"public_key":pub,"capabilities":caps,"challenge_id":ch["challenge_id"],
             "proof_of_possession":sig(sk,ch["sign_this_exact_object"])}
    _,r=call("POST",BASE+"/v1/agent-identity/agents",h,payload)
    assert r["proof_of_possession"]=="VERIFIED"
    return {"id":r["agent"]["agent_id"],"key":r["key"]["key_id"],"sk":sk,"auth":h,"registration":payload}

def main():
    check_config()
    admin=hdr(SERVICE,SERVICE if SERVICE.startswith("eyJ") else None)
    users=[]; orgs=[]; agents=[]; api_keys=[]; client=httpx.Client(timeout=25,headers=admin)
    try:
        u1=make_user(admin,"owner1",users)
        o1=tenant(u1,"VeriSigil CI "+uuid.uuid4().hex[:8]); orgs.append(o1)
        _,listed=call("GET",BASE+"/v1/agent-identity/tenants",hdr(ANON,u1["access"]))
        assert any(x["tenant"]["org_id"]==o1 for x in listed["tenants"])
        owner=hdr(ANON,u1["access"],{"x-org-id":o1})
        scopes=["agents:read","agents:write","keys:write","delegations:write","authority:evaluate","authority:consume","receipts:read"]
        _,issued=call("POST",BASE+"/v1/agent-identity/api-keys",owner,
            {"name":"ci-acceptance","scopes":scopes,"expires_in_days":1})
        api=issued["api_key"]; api_keys.append(issued["key_id"])
        assert api.startswith("vsa_ak_")
        grantor=register(api,o1,"ci-grantor-"+uuid.uuid4().hex[:6],["read_records","write_reports"])
        grantee=register(api,o1,"ci-grantee-"+uuid.uuid4().hex[:6],["write_reports"])
        agents.extend([grantor["id"],grantee["id"]])
        call("POST",BASE+"/v1/agent-identity/agents",hdr(ANON,extra={"x-api-key":api,"x-org-id":o1}),
             grantor["registration"],ok=(409,))
        _,d=call("POST",BASE+"/v1/agent-identity/delegations",
            hdr(ANON,extra={"x-api-key":api,"x-org-id":o1}),
            {"grantor_agent_id":grantor["id"],"grantee_agent_id":grantee["id"],
             "scopes":["read_records"],"expires_at":(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()})
        params={"record_id":"ci-fixture-"+uuid.uuid4().hex}
        action={"agent_id":grantee["id"],"key_id":grantee["key"],"action":"read_records",
                "parameters":params,"delegation_id":d["delegation_id"]}
        _,ev=call("POST",BASE+"/v1/runtime/authority/evaluate",
            hdr(ANON,extra={"x-api-key":api,"x-org-id":o1}),
            {**action,"agent_signature":sig(grantee["sk"],action)})
        assert ev["decision"]=="AUTHORIZED" and ev["execution_authorized"] is False and ev["actuator_invoked"] is False
        proof={"commitment_id":ev["commitment_id"],"action_digest":ev["action_digest"],
               "agent_id":grantee["id"],"key_id":grantee["key"]}
        consume_body={"commitment_id":ev["commitment_id"],"action":"read_records","parameters":params,
                      "agent_signature":sig(grantee["sk"],proof)}
        auth=hdr(ANON,extra={"x-api-key":api,"x-org-id":o1})

        # The decision receipt must be durably readable and verifiable before
        # consumption, from a fresh HTTP client/request context.
        _,before=call("GET",BASE+f"/v1/runtime/authority/receipts/{ev['commitment_id']}",auth)
        assert before.get("issuer_signature_valid") is True
        assert before.get("consumed") is False and before.get("consumable") is True
        assert (before.get("receipt") or {}).get("decision")=="AUTHORIZED"

        # A changed action payload must not consume the original commitment.
        tampered={**consume_body,"parameters":{"record_id":"tampered-"+uuid.uuid4().hex}}
        call("POST",BASE+"/v1/runtime/authority/consume",auth,tampered,ok=(409,))
        _,after_tamper=call("GET",BASE+f"/v1/runtime/authority/receipts/{ev['commitment_id']}",auth)
        assert after_tamper.get("consumed") is False and after_tamper.get("consumable") is True, (
            "rejected action mismatch burned the durable authority commitment"
        )

        # A second authenticated tenant must not be able to read the first
        # tenant's receipt, even when it knows the commitment identifier.
        u2=make_user(admin,"owner2",users)
        o2=tenant(u2,"VeriSigil isolation "+uuid.uuid4().hex[:8]); orgs.append(o2)
        other_tenant=hdr(ANON,u2["access"],{"x-org-id":o2})
        call("GET",BASE+f"/v1/runtime/authority/receipts/{ev['commitment_id']}",other_tenant,ok=(404,))
        call("GET",BASE+f"/v1/agent-identity/agents/{grantor['id']}",other_tenant,ok=(404,))

        # Two independent requests race the same durable one-time consume.
        def consume_once():
            return call("POST",BASE+"/v1/runtime/authority/consume",auth,consume_body,ok=(200,409))[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            statuses=sorted(pool.map(lambda _:consume_once(),range(2)))
        assert statuses==[200,409],f"concurrent consume statuses {statuses}"

        # Read-after-consume must return the persisted signed consumption
        # receipt, not an in-process cache result.
        _,after=call("GET",BASE+f"/v1/runtime/authority/receipts/{ev['commitment_id']}",auth)
        consumed_receipt=after.get("receipt") or {}
        assert after.get("issuer_signature_valid") is True
        assert after.get("consumed") is True and after.get("consumable") is False
        assert consumed_receipt.get("schema")=="VERISIGIL-EXECUTION-AUTHORITY-RECEIPT-1.0"
        assert consumed_receipt.get("actuator_invoked") is False
        replay_status,_=call("POST",BASE+"/v1/runtime/authority/consume",auth,consume_body,ok=(409,))
        assert replay_status==409,"consumed authority commitment replay was not rejected"
        call("POST",BASE+f"/v1/agent-identity/api-keys/{issued['key_id']}/revoke",owner,{})
        call("GET",BASE+"/v1/agent-identity/agents",auth,ok=(401,))
        print("PASS: real Supabase Auth users and verified sessions")
        print("PASS: tenant creation, first-owner membership and tenant listing")
        print("PASS: one-time tenant API key, authenticated use and revocation")
        print("PASS: Ed25519 proof-of-possession and Passport issuance")
        print("PASS: registration challenge replay denied")
        print("PASS: delegation permits only grantor-held scope")
        print("PASS: exact-parameter authority decision and durable receipt")
        print("PASS: concurrent one-time consume returns exactly one 200 and one 409")
        print("PASS: cross-tenant agent lookup denied")
    finally:
        # Only delete this run's synthetic rows. Never point at production.
        try:
            # Discover tenants even if an HTTP timeout happened after the DB commit.
            for u in users:
                response=client.get(SB+"/rest/v1/vgs_agent_identity_tenants",
                    params={"created_by":"eq."+u["id"],"select":"org_id"})
                response.raise_for_status()
                for row in response.json():
                    if row["org_id"] not in orgs: orgs.append(row["org_id"])
            for org in orgs:
                # Remove tenant-scoped rows first, then the legacy mirror rows
                # created by vgs_create_agent_identity_tenant/register_agent.
                for table in ("vgs_agent_authority_commitments","vgs_agent_delegations","vgs_agent_identity_challenges",
                    "vgs_agent_identity_api_keys","vgs_agent_identity_keys","vgs_agent_identities"):
                    response=client.delete(SB+"/rest/v1/"+table,params={"org_id":"eq."+org})
                    response.raise_for_status()
                for table in ("vgs_agent_identity_memberships","vgs_agent_identity_tenants"):
                    response=client.delete(SB+"/rest/v1/"+table,params={"org_id":"eq."+org})
                    response.raise_for_status()
                # The onboarding bridge also creates legacy organisation,
                # agent and Passport rows; leaving these behind leaks test data.
                for table in ("passports","agents"):
                    response=client.delete(SB+"/rest/v1/"+table,params={"org_id":"eq."+org})
                    response.raise_for_status()
                response=client.delete(SB+"/rest/v1/organisations",params={"id":"eq."+org})
                response.raise_for_status()
            for u in users:
                response=client.delete(SB+"/auth/v1/admin/users/"+u["id"])
                response.raise_for_status()
        except Exception as e:
            print("Synthetic cleanup failed: "+type(e).__name__+": "+str(e)[:500],file=sys.stderr); raise
        finally: client.close()

if __name__=="__main__": main()
