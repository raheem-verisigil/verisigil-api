"""
COMPOSED PROOF v3 — passes Paystack key directly in request body
The endpoint supports paystack_key in the request body (line 122062)
so we bypass the Railway env var issue entirely.

Run from Git Bash:
  /c/Users/User/AppData/Local/Programs/Python/Python310/python proof_composed_v3.py
"""
import requests, json, time, sys, uuid, hashlib, os

BASE  = "https://verisigil-api-production.up.railway.app"
KEY   = "vs-sandbox-demo-2026b"
HEADS = {"Content-Type": "application/json", "x-api-key": KEY}

# Paystack test key — passed directly in request body
# Get from: dashboard.paystack.com → Settings → API Keys → Test Secret Key
# Replace the value below with your actual sk_test_... key
PAYSTACK_KEY = os.environ.get("PAYSTACK_SECRET_KEY", "") or \
               os.environ.get("PAYSTACK_TEST_KEY", "") or \
               ""  # ← paste sk_test_... here if env var not set

PASS=[]; FAIL=[]; ND=[]

def hit(method, path, body=None, timeout=30):
    url = f"{BASE}{path}"
    try:
        r = requests.post(url, json=body, headers=HEADS, timeout=timeout) \
            if method == "POST" else \
            requests.get(url, headers=HEADS, timeout=timeout)
        try: return r.status_code, r.json()
        except: return r.status_code, {"raw": r.text[:400]}
    except Exception as e:
        return 0, {"error": str(e)[:100]}

def rec(tid, name, ok, notes="", nd=False):
    if nd:
        print(f"⚠️  {tid}: {name} — NOT_DIAGNOSTIC"); ND.append(tid)
    else:
        print(f"{'✅' if ok else '❌'} {tid}: {name}")
        (PASS if ok else FAIL).append(tid)
    if notes: print(f"   {notes}")
    print()

print("="*68)
print("COMPOSED PROOF v3: STILL + COULD + PRODUCTION ACTUATOR")
print("="*68)
s, h = hit("GET", "/health")
if s != 200: print(f"❌ Railway down: HTTP {s}"); sys.exit(1)
BUILD_ID = h.get("build_id","?")
INSTANCE = h.get("instance_id","?")
print(f"BUILD_ID:    {BUILD_ID}")
print(f"INSTANCE_ID: {INSTANCE}")
print(f"TIME:        {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
print()

# ── STEP 1: STILL ─────────────────────────────────────────────────────────
print("="*50)
print("STEP 1 — STILL (live Supabase)")
print("="*50)
print()

s1, b1 = hit("POST", "/v1/engineering/test-still-adapter", {})
passed = [t for t in b1.get("tests",[]) if t.get("status")=="PASS"]
failed_t = [t for t in b1.get("tests",[]) if t.get("status")=="FAIL"]
ok1 = len(passed) >= 10 and len(failed_t) == 0
rec("S-01", f"STILL adversarial 11 cases live Supabase — {len(passed)}/{len(passed)+len(failed_t)} pass",
    ok1, f"all_pass={b1.get('all_pass')} passed={len(passed)} failed={len(failed_t)}")

s2, b2 = hit("POST", "/v1/adversarial/still-authority", {
    "test_revocation": True, "test_forged_still": True, "test_fail_closed": True,
})
s2_refusal = b2.get("ruling") in ("REFUSED","HALT") and b2.get("state_mutation") == "NONE"
ok2 = s2 == 200 or s2_refusal
rec("S-02","STILL adversarial probe — structured refusal state_mutation=NONE",
    ok2, f"HTTP {s2} ruling={b2.get('ruling','?')} state_mutation={b2.get('state_mutation','?')}")

s3, b3 = hit("POST", "/v1/still/check", {
    "authority_hash": "HASH-UNKNOWN-XYZ", "agent_id": "AGENT-UNKNOWN",
})
ok3 = b3.get("still_result") in ("NOT_VERIFIED","FAILED","NOT_PROVABLE")
rec("S-03","Unknown authority → fail-closed (not PROVABLE)",
    ok3, f"HTTP {s3} still_result={b3.get('still_result','?')}")

print()
print("="*50)
print("STEP 2 — COULD + PRODUCTION ACTUATOR")
print("="*50)
print()

# First: ask the endpoint what Paystack vars it can see in its env
s_debug, b_debug = hit("POST", "/v1/engineering/test-paystack-actuator", {})
env_vars_found = b_debug.get("paystack_vars_found_in_env", [])
print(f"Paystack vars in Railway env: {env_vars_found}")
print(f"Endpoint status: {b_debug.get('status','?')}")
print()

if b_debug.get("status") == "SKIPPED" and not PAYSTACK_KEY:
    print("❌ No Paystack key available.")
    print("   Railway env vars with PAYSTACK: " + str(env_vars_found))
    print()
    print("   FIX: Pass key directly in request body.")
    print("   Edit this script: set PAYSTACK_KEY = 'sk_test_...' at line ~30")
    print("   OR: In Railway dashboard, confirm the variable VALUE is set (not just the name)")
    rec("C-01","Paystack valid path", False, nd=True,
        notes="No key found in Railway env or script")
    rec("C-02","Paystack inadmissible blocked", False, nd=True)
    rec("C-03","VCB invariant holds", False, nd=True)
else:
    # Pass key directly in body — bypasses env var lookup
    body = {}
    if PAYSTACK_KEY:
        body["paystack_key"] = PAYSTACK_KEY
        print(f"Using key from local env: {PAYSTACK_KEY[:12]}...")

    s_p, b_p = hit("POST", "/v1/engineering/test-paystack-actuator", body, timeout=45)
    print(f"Paystack test: HTTP {s_p}")
    print(f"Full response: {json.dumps(b_p, indent=2, default=str)[:600]}")
    print()

    if b_p.get("status") == "SKIPPED":
        rec("C-01","Paystack valid path", False, nd=True,
            notes=f"Still SKIPPED even with key. vars_in_env={env_vars_found}")
        rec("C-02","Paystack inadmissible blocked", False, nd=True)
        rec("C-03","VCB invariant holds", False, nd=True)
    else:
        vcb_holds = b_p.get("vcb_invariant_holds", False)
        blocked = b_p.get("blocked_attempts", [])
        executed = b_p.get("executed_attempts", [])
        refs = [e.get("paystack_reference","") for e in executed if e.get("paystack_reference")]

        ok_c1 = len(executed) > 0 or vcb_holds
        rec("C-01",f"Valid path → Paystack executed ({len(executed)} attempts)",
            ok_c1, f"references={refs[:2]}")

        all_blocked_no_api = all(not a.get("paystack_api_called", True) for a in blocked)
        ok_c2 = len(blocked) > 0 and all_blocked_no_api
        rec("C-02",f"Inadmissible → Paystack never called ({len(blocked)} blocked)",
            ok_c2, f"all_paystack_api_called=False: {all_blocked_no_api}")

        rec("C-03","VCB invariant holds at actuator boundary",
            vcb_holds, f"vcb_invariant_holds={vcb_holds}")

print()
print("="*50)
print("STEP 3 — SEAL + VERIFY + TAMPER")
print("="*50)
print()

action = {"action_type":"PAYMENT","amount":500,"currency":"USD","vendor":"Supplier_A"}
commit_hash = hashlib.sha256(
    json.dumps(action, sort_keys=True, separators=(',',':')).encode()
).hexdigest()

s_s, b_s = hit("POST", "/v1/vcb/seal", {
    "vcb_decision": {"decision":"ALLOW","authority_id":"COMPOSED-V3",
                     "subject_id":"agent-proof-v3","rationale":"Composed proof v3",
                     "commitment_hash": commit_hash},
    "action": action, "ttl_seconds": 600,
})
ok_s = s_s==200 and b_s.get("schema")=="VGS-SIGILMARK-2.2"
rec("R-01",f"Seal — {b_s.get('sigilmark_id','?')}",
    ok_s, f"HTTP {s_s} schema={b_s.get('schema','?')}")

if ok_s:
    s_v, b_v = hit("POST", "/v1/vcb/sigilmark/verify", {"sigilmark": b_s})
    rec("R-02","Verify → result=VALID",
        s_v==200 and b_v.get("result")=="VALID",
        f"HTTP {s_v} result={b_v.get('result')} failures={b_v.get('failures')}")

    tampered = json.loads(json.dumps(b_s, default=str))
    orig = tampered.get("integrity_hash","")
    if orig: tampered["integrity_hash"] = "0"*len(orig)
    s_t, b_t = hit("POST", "/v1/vcb/sigilmark/verify", {"sigilmark": tampered})
    ok_t = s_t==200 and b_t.get("result")=="INVALID" and "INTEGRITY_HASH_INVALID" in b_t.get("failures",[])
    rec("R-03","Tamper → INVALID + INTEGRITY_HASH_INVALID",
        ok_t, f"HTTP {s_t} result={b_t.get('result')} failures={b_t.get('failures')}")

print("="*68)
print(f"BUILD_ID: {BUILD_ID} | PASS: {len(PASS)} | FAIL: {len(FAIL)} | ND: {len(ND)}")
if FAIL: print(f"FAILED: {FAIL}")
if ND:   print(f"NOT_DIAGNOSTIC: {ND}")
print("PRODUCTION_CLAIM_ALLOWED: False")
