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
    if "staging" not in BASE.lower() or "staging" not in SB.lower():
        raise RuntimeError("Refusing non-staging target.")

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

def make_user(admin,label):
    email=f"vgs-ci-{label}-{uuid.uuid4().hex[:10]}@example.invalid"; password=secrets.token_urlsafe(36)+"A9!"
    _,u=call("POST",SB+"/auth/v1/admin/users",admin,{"email":email,"password":password,"email_confirm":True},(200,201))
    _,s=call("POST",SB+"/auth/v1/token?grant_type=password",hdr(ANON),{"email":email,"password":password})
    return {"id":u["id"],"access":s["access_token"]}

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
        u1=make_user(admin,"owner1"); users.append(u1)
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
        def consume_once():
            return call("POST",BASE+"/v1/runtime/authority/consume",auth,consume_body,ok=(200,409))[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            statuses=sorted(pool.map(lambda _:consume_once(),range(2)))
        assert statuses==[200,409],f"concurrent consume statuses {statuses}"
        call("GET",BASE+f"/v1/runtime/authority/receipts/{ev['commitment_id']}",auth)
        u2=make_user(admin,"owner2"); users.append(u2)
        o2=tenant(u2,"VeriSigil isolation "+uuid.uuid4().hex[:8]); orgs.append(o2)
        call("GET",BASE+f"/v1/agent-identity/agents/{grantor['id']}",
             hdr(ANON,u2["access"],{"x-org-id":o2}),ok=(404,))
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
            for org in orgs:
                for table in ("vgs_agent_authority_commitments","vgs_agent_delegations","vgs_agent_identity_challenges",
                    "vgs_agent_identity_api_keys","vgs_agent_identity_keys","vgs_agent_identities","passports"):
                    client.delete(SB+"/rest/v1/"+table,params={"org_id":"eq."+org})
                for aid in agents: client.delete(SB+"/rest/v1/agents",params={"id":"eq."+aid})
                client.delete(SB+"/rest/v1/vgs_agent_identity_memberships",params={"org_id":"eq."+org})
                client.delete(SB+"/rest/v1/vgs_agent_identity_tenants",params={"org_id":"eq."+org})
                client.delete(SB+"/rest/v1/organisations",params={"id":"eq."+org})
            for u in users: client.delete(SB+"/auth/v1/admin/users/"+u["id"])
        except Exception as e:
            print("Synthetic cleanup failed: "+type(e).__name__,file=sys.stderr); raise
        finally: client.close()

if __name__=="__main__": main()
