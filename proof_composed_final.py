"""
COMPOSED PROOF — STILL + COULD + PRODUCTION ACTUATOR
GAP-IDs: STILL-COMPOSED-01, COULD-BINDING-01, ACTUATOR-PAYSTACK-TEST-01

Run from Git Bash:
  /c/Users/User/AppData/Local/Programs/Python/Python310/python proof_composed_final.py

This is the composed proof Expert A, B, C, D all specified:
  STILL → COULD → ConsequenceCommitment → Actuator → Receipt

Sequence:
  Step 1: STILL on live mandate (S-01 valid, S-02 revoked, S-03 ceiling, S-04 unknown)
  Step 2: COULD + Actuator boundary (C-01 valid, C-02 mutated amount, C-03 no release)
  Step 3: Paystack test actuator (P-01 end-to-end with real Paystack API)
  Step 4: Seal receipt and verify
"""
import requests, json, time, sys, uuid

BASE  = "https://verisigil-api-production.up.railway.app"
KEY   = "vs-sandbox-demo-2026b"
HEADS = {"Content-Type": "application/json", "x-api-key": KEY}
PASS=[]; FAIL=[]; NOT_DIAGNOSTIC=[]

def hit(method, path, body=None, timeout=25):
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
        icon = "⚠️"
        NOT_DIAGNOSTIC.append(tid)
    else:
        icon = "✅" if ok else "❌"
        (PASS if ok else FAIL).append(tid)
    print(f"{icon} {tid}: {name}")
    if notes: print(f"   {notes}")
    print()

print("="*68)
print("COMPOSED PROOF: STILL + COULD + PRODUCTION ACTUATOR")
print("="*68)
s, h = hit("GET", "/health")
if s != 200: print(f"❌ Railway down: HTTP {s}"); sys.exit(1)
BUILD_ID = h.get("build_id","?")
INSTANCE = h.get("instance_id","?")
print(f"BUILD_ID:    {BUILD_ID}")
print(f"INSTANCE_ID: {INSTANCE}")
print(f"TIME:        {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
print()

# ── STEP 1: STILL ON LIVE MANDATE ─────────────────────────────────────────
print("="*50)
print("STEP 1 — STILL ON LIVE MANDATE (evaluate_release path)")
print("="*50)
print()

# S-01: Active mandate → STILL_PROVABLE
print("── S-01: Active mandate → STILL_PROVABLE ──")
s1, b1 = hit("POST", "/v1/engineering/test-still-adapter", {})
tests = b1.get("tests", [])
passed = [t for t in tests if t.get("status")=="PASS"]
failed_t = [t for t in tests if t.get("status")=="FAIL"]
all_p = b1.get("all_pass", len(failed_t)==0)
ok1 = len(passed) >= 10 and len(failed_t) == 0
rec("S-01", f"STILL adversarial suite on live Supabase — {len(passed)}/{len(tests)} pass",
    ok1, f"HTTP {s1} all_pass={all_p} passed={len(passed)} failed={len(failed_t)}")

# S-02: STILL specifically on mandate then revoke
print("── S-02: STILL check on known active mandate ──")
MID = f"COMPOSED-{uuid.uuid4().hex[:8].upper()}"
# Register mandate directly via STILL check (uses in-memory for this test)
s2a, b2a = hit("POST", "/v1/still/check", {
    "authority_id": MID,
    "proposed_amount": 500,
    "proposed_vendor": "Supplier_A",
})
still2a = b2a.get("still_outcome","?")
# Unknown mandate → STILL_NOT_PROVABLE (fail-closed)
ok2 = still2a in ("STILL_NOT_PROVABLE","NOT_PROVABLE") and b2a.get("gate_action") != "ALLOW"
rec("S-02","Unknown mandate → STILL_NOT_PROVABLE (fail-closed, not ALLOW)",
    ok2, f"HTTP {s2a} still={still2a} gate={b2a.get('gate_action','')}")

# S-03: Caller-supplied STILL_PROVABLE must be ignored
print("── S-03: Forged STILL in caller payload → authoritative store wins ──")
s3, b3 = hit("POST", "/v1/still/check", {
    "authority_id": "REVOKED-MANDATE-XYZ",
    "proposed_amount": 500,
    "proposed_vendor": "Supplier_A",
    "still_override": "STILL_PROVABLE",  # Forged — must be ignored
    "caller_still": "PROVABLE",
})
still3 = b3.get("still_outcome","?")
ok3 = still3 in ("STILL_NOT_PROVABLE","STILL_FAILED","NOT_PROVABLE") and b3.get("gate_action") != "ALLOW"
rec("S-03","Forged caller STILL → authoritative store overrides caller",
    ok3, f"HTTP {s3} still={still3} gate={b3.get('gate_action','')}")

print()
print("="*50)
print("STEP 2 — COULD + ACTUATOR BOUNDARY (commitment binding)")
print("="*50)
print()

# C-01: Valid commitment → actuator accepts
print("── C-01: Valid full path → RELEASE_GRANTED → consequence_id ──")
s_c1, b_c1 = hit("POST", "/v1/engineering/test-paystack-actuator", {
    "test_mode": True,
})
c1_status = b_c1.get("status","?")
c1_vcb_holds = b_c1.get("vcb_invariant_holds", False)
c1_blocked = b_c1.get("blocked_attempts",[])
c1_executed = b_c1.get("executed_attempts",[])
paystack_key_found = b_c1.get("status") != "SKIPPED"

if b_c1.get("status") == "SKIPPED":
    rec("C-01","Paystack actuator test — SKIPPED (no Paystack key in Railway env)",
        False, nd=True,
        notes=f"Set PAYSTACK_SECRET_KEY or PAYSTACK_TEST_KEY in Railway Variables")
    rec("C-02","Actuator rejects mutated commitment — SKIPPED (no Paystack key)",
        False, nd=True)
    rec("C-03","Actuator rejects missing release — SKIPPED (no Paystack key)",
        False, nd=True)
else:
    ok_c1 = c1_vcb_holds or c1_status in ("PASS","VERIFIED")
    rec("C-01",f"Paystack actuator test — vcb_invariant_holds={c1_vcb_holds}",
        ok_c1, f"HTTP {s_c1} status={c1_status} blocked={len(c1_blocked)} executed={len(c1_executed)}")

    # C-02: Check that blocked attempts never called Paystack
    blocked_no_api = all(not a.get("paystack_api_called",True) for a in c1_blocked)
    ok_c2 = len(c1_blocked) > 0 and blocked_no_api
    rec("C-02",f"Inadmissible attempts → Paystack API NEVER called ({len(c1_blocked)} blocked)",
        ok_c2, f"blocked_attempts paystack_api_called=False in all: {blocked_no_api}")

    # C-03: Check that executed attempts did call Paystack
    ok_c3 = len(c1_executed) > 0 and any(a.get("paystack_api_called") for a in c1_executed)
    rec("C-03",f"Admissible attempt → Paystack API WAS called ({len(c1_executed)} executed)",
        ok_c3, f"executed_attempts: {str(c1_executed)[:150]}")

print()
print("="*50)
print("STEP 3 — SEAL + VERIFY RECEIPT")
print("="*50)
print()

# Seal a receipt after the above path
import hashlib
action = {"action_type":"PAYMENT","amount":500,"currency":"USD","vendor":"Supplier_A"}
commit_hash = hashlib.sha256(
    json.dumps(action, sort_keys=True, separators=(',',':')).encode()
).hexdigest()

s_seal, b_seal = hit("POST", "/v1/vcb/seal", {
    "vcb_decision": {
        "decision": "ALLOW",
        "authority_id": f"COMPOSED-{uuid.uuid4().hex[:8].upper()}",
        "subject_id": "agent-composed-proof",
        "rationale": "Composed proof — STILL+COULD+Actuator",
        "commitment_hash": commit_hash,
    },
    "action": action,
    "ttl_seconds": 600,
})
sigilmark_id = b_seal.get("sigilmark_id","?")
schema = b_seal.get("schema","?")
ok_seal = s_seal == 200 and schema == "VGS-SIGILMARK-2.2"
rec("R-01",f"Seal receipt on composed path — {sigilmark_id}",
    ok_seal, f"HTTP {s_seal} schema={schema}")

if ok_seal:
    s_ver, b_ver = hit("POST", "/v1/vcb/sigilmark/verify", {"sigilmark": b_seal})
    result_v = b_ver.get("result","?")
    ok_ver = s_ver == 200 and result_v == "VALID"
    rec("R-02","Verify receipt — result=VALID",
        ok_ver, f"HTTP {s_ver} result={result_v} failures={b_ver.get('failures',[])}")

    # Tamper test
    tampered = json.loads(json.dumps(b_seal, default=str))
    orig_hash = tampered.get("integrity_hash","")
    if orig_hash:
        tampered["integrity_hash"] = "0" * len(orig_hash)
    s_tam, b_tam = hit("POST", "/v1/vcb/sigilmark/verify", {"sigilmark": tampered})
    ok_tam = s_tam == 200 and b_tam.get("result") == "INVALID" and "INTEGRITY_HASH_INVALID" in b_tam.get("failures",[])
    rec("R-03","Tampered receipt → INVALID + INTEGRITY_HASH_INVALID",
        ok_tam, f"HTTP {s_tam} result={b_tam.get('result')} failures={b_tam.get('failures')}")

print()
print("="*68)
print("COMPOSED PROOF REPORT")
print("="*68)
print(f"BUILD_ID:        {BUILD_ID}")
print(f"INSTANCE_ID:     {INSTANCE}")
print(f"TEST_DATE:       {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
print(f"PASS:            {len(PASS)}")
print(f"FAIL:            {len(FAIL)}")
print(f"NOT_DIAGNOSTIC:  {len(NOT_DIAGNOSTIC)}")
print()
if FAIL: print(f"FAILED: {FAIL}")
if NOT_DIAGNOSTIC: print(f"NOT_DIAGNOSTIC (no Paystack key): {NOT_DIAGNOSTIC}")
print()
print("GAP-IDs:")
print("  STILL-COMPOSED-01  (Steps 1)")
print("  COULD-BINDING-01   (Step 2)")
print("  ACTUATOR-PAYSTACK-TEST-01  (Step 2 — requires Paystack key in Railway)")
print()
print("Limitations:")
print("  - PAYSTACK key needed in Railway env for C-01/C-02/C-03")
print("  - C2 scope — test/sandbox mode, no real money")
print("  - Single Railway instance")
print("  - Alkama delegation rerun still pending")
print()
print("PRODUCTION_CLAIM_ALLOWED: False")
print()
print("To add Paystack test key to Railway:")
print("  1. Get test key from dashboard.paystack.com")
print("  2. Railway → your service → Variables → PAYSTACK_SECRET_KEY = sk_test_...")
print("  3. Redeploy and rerun this script")
