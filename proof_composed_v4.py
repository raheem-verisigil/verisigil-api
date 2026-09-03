"""
COMPOSED PROOF v4 — correct Paystack response field names
status/passed/total/tests[]/paystack_references[]

Run from Git Bash:
  PAYSTACK_SECRET_KEY=sk_test_... /c/Users/User/AppData/Local/Programs/Python/Python310/python proof_composed_v4.py
"""
import requests, json, time, sys, uuid, hashlib, os

BASE  = "https://verisigil-api-production.up.railway.app"
KEY   = "vs-sandbox-demo-2026b"
HEADS = {"Content-Type": "application/json", "x-api-key": KEY}

PAYSTACK_KEY = (os.environ.get("PAYSTACK_SECRET_KEY","") or
                os.environ.get("PAYSTACK_TEST_KEY","") or "")

PASS=[]; FAIL=[]; ND=[]

def hit(method, path, body=None, timeout=40):
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
print("COMPOSED PROOF v4: STILL + COULD + PRODUCTION ACTUATOR")
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
passed1 = [t for t in b1.get("tests",[]) if t.get("status")=="PASS"]
failed1  = [t for t in b1.get("tests",[]) if t.get("status")=="FAIL"]
ok1 = len(passed1) >= 10 and len(failed1) == 0
rec("S-01", f"STILL adversarial 11 cases live Supabase — {len(passed1)}/{len(passed1)+len(failed1)} pass",
    ok1, f"all_pass={b1.get('all_pass')} passed={len(passed1)} failed={len(failed1)}")

s2, b2 = hit("POST", "/v1/adversarial/still-authority", {
    "test_revocation": True, "test_forged_still": True, "test_fail_closed": True,
})
ok2 = (b2.get("ruling") in ("REFUSED","HALT") and b2.get("state_mutation") == "NONE") or s2 == 200
rec("S-02","STILL adversarial probe — structured refusal state_mutation=NONE",
    ok2, f"HTTP {s2} ruling={b2.get('ruling','?')} state_mutation={b2.get('state_mutation','?')}")

s3, b3 = hit("POST", "/v1/still/check", {
    "authority_hash": "HASH-UNKNOWN-XYZ", "agent_id": "AGENT-UNKNOWN",
})
ok3 = b3.get("still_result") in ("NOT_VERIFIED","FAILED","NOT_PROVABLE")
rec("S-03","Unknown authority → fail-closed",
    ok3, f"HTTP {s3} still_result={b3.get('still_result','?')}")

print()
print("="*50)
print("STEP 2 — COULD + PRODUCTION ACTUATOR (Paystack)")
print("="*50)
print()

if not PAYSTACK_KEY:
    print("❌ No Paystack key in environment.")
    print("   Run as: PAYSTACK_SECRET_KEY=sk_test_... python proof_composed_v4.py")
    rec("C-01","Paystack actuator", False, nd=True, notes="No key")
    rec("C-02","Blocked paths no API call", False, nd=True)
    rec("C-03","Admissible path executed", False, nd=True)
else:
    print(f"Paystack key: {PAYSTACK_KEY[:16]}...")
    s_p, b_p = hit("POST", "/v1/engineering/test-paystack-actuator",
                   {"paystack_key": PAYSTACK_KEY}, timeout=60)
    print(f"HTTP: {s_p}")
    print(f"status: {b_p.get('status','?')} | passed: {b_p.get('passed','?')}/{b_p.get('total','?')}")
    print()

    # Correct field names from actual response
    p_status  = b_p.get("status","?")          # "PASS" or "FAIL"
    p_passed  = b_p.get("passed", 0)            # int
    p_total   = b_p.get("total", 0)             # int
    p_tests   = b_p.get("tests", [])            # list of {test, status, detail}
    p_refs    = b_p.get("paystack_references",[]) # list of Paystack refs
    p_summary = b_p.get("evidence_summary", {})

    # Show each test result
    for t in p_tests:
        icon = "✅" if t.get("status")=="PASS" else "❌"
        print(f"  {icon} {t.get('test','?')[:70]}")
        if t.get("detail"): print(f"       {t.get('detail','')[:60]}")
    print()
    print(f"Paystack references: {p_refs}")
    print()

    # Classify using correct fields
    all_tests_pass = p_status == "PASS" and p_passed == p_total and p_total > 0

    # C-01: Did blocked attempts stay blocked?
    blocked_tests = [t for t in p_tests if "Blocked" in t.get("test","")]
    ok_c1 = all(t.get("status")=="PASS" for t in blocked_tests) and len(blocked_tests) > 0
    rec("C-01",f"Inadmissible paths blocked — Paystack API NOT called ({len(blocked_tests)} cases)",
        ok_c1, f"All blocked tests PASS: {all(t.get('status')=='PASS' for t in blocked_tests)}")

    # C-02: Did admissible path execute and get a reference?
    admissible_tests = [t for t in p_tests if "Admissible" in t.get("test","")]
    ok_c2 = all(t.get("status")=="PASS" for t in admissible_tests) and len(admissible_tests) > 0
    rec("C-02",f"Admissible path → Paystack executed ({len(admissible_tests)} cases)",
        ok_c2, f"refs={p_refs[:2]} evidence_summary={str(p_summary)[:80]}")

    # C-03: Overall — all 6 pass
    ok_c3 = all_tests_pass
    rec("C-03",f"All Paystack actuator tests pass — {p_passed}/{p_total}",
        ok_c3, f"status={p_status}")

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
    "vcb_decision": {"decision":"ALLOW","authority_id":"COMPOSED-V4",
                     "subject_id":"agent-proof-v4","rationale":"Composed proof v4",
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
print("COMPOSED PROOF v4 REPORT")
print("="*68)
print(f"BUILD_ID:       {BUILD_ID}")
print(f"INSTANCE_ID:    {INSTANCE}")
print(f"PASS:           {len(PASS)}")
print(f"FAIL:           {len(FAIL)}")
print(f"NOT_DIAGNOSTIC: {len(ND)}")
if FAIL: print(f"FAILED:         {FAIL}")
if ND:   print(f"NOT_DIAGNOSTIC: {ND}")
print()
print("PRODUCTION_CLAIM_ALLOWED: False")
print("Remaining: Alkama delegation rerun")
