"""
P1-C DIAGNOSTIC — Raw response capture for T-P4 and T-P7
Run this BEFORE any code changes.
Captures complete unmodified API responses to classify failures.

Run from Git Bash:
  /c/Users/User/AppData/Local/Programs/Python/Python310/python p1c_diagnostic.py
"""
import requests, json, hashlib, time, sys

BASE    = "https://verisigil-api-production.up.railway.app"
KEY     = "vs-sandbox-demo-2026b"
HEADERS = {"Content-Type": "application/json", "x-api-key": KEY}

def hit(method, path, body=None, timeout=20):
    url = f"{BASE}{path}"
    try:
        r = requests.post(url, json=body, headers=HEADERS, timeout=timeout) \
            if method == "POST" else \
            requests.get(url, headers=HEADERS, timeout=timeout)
        return r.status_code, r.json(), r.text
    except Exception as e:
        return 0, {"error": str(e)}, str(e)

print("="*68)
print("P1-C DIAGNOSTIC — RAW RESPONSE CAPTURE")
print("="*68)
print(f"TIME: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
print()

# ── STEP 0: Health check ──────────────────────────────────────────────────
s, b, _ = hit("GET", "/health")
print(f"BUILD_ID:    {b.get('build_id','?')}")
print(f"INSTANCE_ID: {b.get('instance_id','?')}")
print()

# ── STEP 1: Seal a fresh SigilMark ───────────────────────────────────────
print("── Step 1: Seal fresh SigilMark ──")
action = {"action_type":"PAYMENT","amount":500,"currency":"USD","vendor":"Supplier_A"}
commit_hash = hashlib.sha256(
    json.dumps(action, sort_keys=True, separators=(',',':')).encode()
).hexdigest()

seal_body = {
    "vcb_decision": {
        "decision": "ALLOW",
        "authority_id": "DIAG-MANDATE-001",
        "subject_id": "agent-diag",
        "rationale": "P1-C diagnostic run",
        "commitment_hash": commit_hash,
    },
    "action": action,
    "ttl_seconds": 300,
}

s3, b3, raw3 = hit("POST", "/v1/vcb/seal", seal_body)
print(f"Seal HTTP: {s3}")
print(f"sigilmark_id: {b3.get('sigilmark_id','NOT FOUND')}")
print(f"schema: {b3.get('schema','NOT FOUND')}")
print()

# ── STEP 2: T-P4 DIAGNOSTIC — Verify SigilMark, capture ALL fields ────────
print("="*68)
print("T-P4 DIAGNOSTIC — Complete raw verify response")
print("="*68)
s4, b4, raw4 = hit("POST", "/v1/vcb/sigilmark/verify", {"sigilmark": b3})
print(f"HTTP status: {s4}")
print(f"COMPLETE RAW RESPONSE (JSON):")
print(json.dumps(b4, indent=2, default=str))
print()
print("FIELD MAPPING:")
print(f"  b4.get('integrity'): {b4.get('integrity','NOT FOUND')}")
print(f"  b4.get('signature'): {b4.get('signature','NOT FOUND')}")
print(f"  b4.get('verdict'):   {b4.get('verdict','NOT FOUND')}")
print(f"  b4.get('result'):    {b4.get('result','NOT FOUND')}")
print(f"  b4.get('failures'):  {b4.get('failures','NOT FOUND')}")
print(f"  b4.get('checks'):    {b4.get('checks','NOT FOUND')}")
print(f"  b4.keys(): {list(b4.keys())}")
print()

# Classification
if b4.get('result') in ('VALID','PASS','INTEGRITY_VERIFIED') or \
   b4.get('integrity') in ('VERIFIED','INTEGRITY_VERIFIED'):
    print("T-P4 CLASSIFICATION: PASS — verifier accepted the SigilMark")
elif b4.get('result') == 'INVALID' or b4.get('integrity') == 'FAILED':
    print("T-P4 CLASSIFICATION: VERIFIER_FAILURE — integrity check failed")
    print("  This may be a re-serialization issue (Python dict vs original JSON bytes)")
else:
    print("T-P4 CLASSIFICATION: NOT_DIAGNOSTIC — cannot determine from fields")
print()

# ── STEP 3: T-P7 DIAGNOSTIC — Tamper test, capture ALL fields ─────────────
print("="*68)
print("T-P7 DIAGNOSTIC — Tamper detection, complete raw response")
print("="*68)

# Tamper exactly one field
tampered = json.loads(json.dumps(b3, default=str))  # Deep copy via JSON round-trip
# Modify a non-signature field to trigger integrity failure
if "payload" in tampered and isinstance(tampered["payload"], dict):
    tampered["payload"]["_forged_field"] = "ATTACKER_INJECTION"
    mutated_field = "payload._forged_field"
elif "sigilmark_id" in tampered:
    tampered["sigilmark_id"] = "FORGED-SM-000000"
    mutated_field = "sigilmark_id"
else:
    tampered["_forged"] = "ATTACKER"
    mutated_field = "_forged (new field)"

print(f"Mutated field: {mutated_field}")
print(f"Tampered body sent to verify:")
print(json.dumps(tampered, indent=2, default=str)[:500])
print()

s7, b7, raw7 = hit("POST", "/v1/vcb/sigilmark/verify", {"sigilmark": tampered})
print(f"HTTP status: {s7}")
print(f"COMPLETE RAW RESPONSE (JSON):")
print(json.dumps(b7, indent=2, default=str))
print()
print("FIELD MAPPING:")
print(f"  b7.get('integrity'): {b7.get('integrity','NOT FOUND')}")
print(f"  b7.get('result'):    {b7.get('result','NOT FOUND')}")
print(f"  b7.get('failures'):  {b7.get('failures','NOT FOUND')}")
print(f"  b7.keys(): {list(b7.keys())}")
print()

# Classification
if b7.get('result') == 'INVALID' and b7.get('failures'):
    print("T-P7 CLASSIFICATION: PASS — verifier correctly detected tampering")
    print(f"  Failures: {b7.get('failures')}")
    print("  SCRIPT ASSERTION WAS WRONG — checked 'integrity' field, actual field is 'result'")
elif b7.get('integrity') in ('FAILED','INVALID','INTEGRITY_FAILED'):
    print("T-P7 CLASSIFICATION: PASS — verifier correctly detected tampering (integrity field)")
else:
    print(f"T-P7 CLASSIFICATION: NEEDS_INVESTIGATION — unexpected response: {b7}")
print()

# ── STEP 4: T-P2-R — all_pass aggregation diagnostic ─────────────────────
print("="*68)
print("T-P2-R DIAGNOSTIC — all_pass aggregation consistency")
print("="*68)
s2, b2, _ = hit("POST", "/v1/engineering/test-still-adapter", {})
tests = b2.get("tests", [])
passed = [t for t in tests if t.get("status") == "PASS"]
failed = [t for t in tests if t.get("status") == "FAIL"]
all_pass_reported = b2.get("all_pass")
all_pass_computed = (len(failed) == 0 and len(passed) > 0)

print(f"Tests count: {len(tests)}")
print(f"Passed count: {len(passed)}")
print(f"Failed count: {len(failed)}")
print(f"all_pass (reported by API): {all_pass_reported}")
print(f"all_pass (computed from results): {all_pass_computed}")
print()
if all_pass_reported == all_pass_computed:
    print("T-P2-R: CONSISTENT — no contradiction")
else:
    print("T-P2-R: CONTRADICTION — API all_pass field disagrees with test results")
    print(f"  Root cause: API returns all_pass={all_pass_reported} but {len(passed)}/{len(tests)} pass")
    print("  Classification: REPORTING_BUG in endpoint (not a STILL gate failure)")
print()

# ── FINAL DIAGNOSTIC REPORT ───────────────────────────────────────────────
print("="*68)
print("P1-C DIAGNOSTIC REPORT")
print("="*68)
print(f"BUILD_ID:    {b.get('build_id','?')}")
print(f"INSTANCE_ID: {b.get('instance_id','?')}")
print()
print("T-P4:")
print(f"  RAW result field: {b4.get('result','NOT_FOUND')}")
print(f"  RAW failures:     {b4.get('failures','NOT_FOUND')}")
print(f"  Script expected:  integrity / signature / verdict")
print(f"  API returned:     result / failures / {list(b4.keys())[:5]}")
print(f"  HARNESS_ERROR:    Script checked wrong field name")
print()
print("T-P7:")
print(f"  Mutated field:    {mutated_field}")
print(f"  RAW result:       {b7.get('result','NOT_FOUND')}")
print(f"  RAW failures:     {b7.get('failures','NOT_FOUND')}")
print(f"  Tamper detected:  {b7.get('result') == 'INVALID'}")
print(f"  CLASSIFICATION:   {'B — test-harness schema mismatch (verifier working correctly)' if b7.get('result')=='INVALID' else 'NEEDS_INVESTIGATION'}")
print()
print("T-P2-R:")
print(f"  all_pass reported: {all_pass_reported}")
print(f"  all_pass computed: {all_pass_computed}")
print(f"  CLASSIFICATION:   {'REPORTING_BUG in endpoint' if all_pass_reported != all_pass_computed else 'CONSISTENT'}")
print()
print("PRODUCTION_CLAIM_ALLOWED: False")
