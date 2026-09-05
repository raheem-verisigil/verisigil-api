"""
P1-C SEAL DIAGNOSTIC — smallest possible test
Step 1: health check
Step 2: one seal request, full raw response
Nothing else until seal succeeds.

Run from Git Bash:
  /c/Users/User/AppData/Local/Programs/Python/Python310/python p1c_seal_only.py
"""
import requests, json, hashlib, time, sys

BASE    = "https://verisigil-api-production.up.railway.app"
KEY     = "vs-sandbox-demo-2026b"
HEADERS = {"Content-Type": "application/json", "x-api-key": KEY}

def hit(method, path, body=None, timeout=30):
    url = f"{BASE}{path}"
    try:
        r = requests.post(url, json=body, headers=HEADERS, timeout=timeout) \
            if method == "POST" else \
            requests.get(url, headers=HEADERS, timeout=timeout)
        try:    return r.status_code, r.json(), r.elapsed.total_seconds()
        except: return r.status_code, {"raw": r.text[:500]}, r.elapsed.total_seconds()
    except Exception as e:
        return 0, {"error": str(e)}, 0

print("="*68)
print("P1-C SEAL DIAGNOSTIC — minimal sequence")
print("="*68)
print(f"TIME: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
print()

# ── STEP 1: HEALTH ────────────────────────────────────────────────────────
print("── Step 1: Health ──")
s_h, b_h, t_h = hit("GET", "/health")
print(f"HTTP:            {s_h}")
print(f"BUILD_ID:        {b_h.get('build_id','NOT FOUND')}")
print(f"INSTANCE_ID:     {b_h.get('instance_id','NOT FOUND')}")
print(f"PROCESS_STARTED: {b_h.get('process_started_at','NOT FOUND')}")
print(f"UPTIME_SECONDS:  {b_h.get('uptime_seconds','NOT FOUND')}")
print(f"RESPONSE_TIME:   {t_h:.3f}s")
print()

if s_h != 200:
    print("❌ Health check failed — Railway is down or unreachable")
    print(f"   Response: {b_h}")
    sys.exit(1)

# ── STEP 2: SMALLEST VALID SEAL ───────────────────────────────────────────
print("── Step 2: Seal (minimal valid payload) ──")
action = {"action_type": "PAYMENT", "amount": 100, "currency": "USD", "vendor": "Supplier_A"}
commit_hash = hashlib.sha256(
    json.dumps(action, sort_keys=True, separators=(',', ':')).encode()
).hexdigest()

seal_body = {
    "vcb_decision": {
        "decision": "ALLOW",
        "authority_id": "DIAG-V3-001",
        "subject_id": "agent-diag-v3",
        "rationale": "P1-C v3 minimal seal test",
        "commitment_hash": commit_hash,
    },
    "action": action,
    "ttl_seconds": 600,
}

print(f"Sending payload:")
print(json.dumps(seal_body, indent=2))
print()

s3, b3, t3 = hit("POST", "/v1/vcb/seal", seal_body)
print(f"HTTP:            {s3}")
print(f"RESPONSE_TIME:   {t3:.3f}s")
print()
print("COMPLETE RAW RESPONSE:")
print(json.dumps(b3, indent=2, default=str))
print()

if s3 == 502:
    print("❌ SEAL RETURNED 502 — Application failed to respond")
    print()
    print("STOP. Do not proceed to verify.")
    print("Check Railway logs using request_id:", b3.get('request_id','?'))
    print()
    print("Possible causes:")
    print("  A. Application crashed/restarted during request")
    print("  B. Request timed out (>30s)")
    print("  C. Railway proxy failure")
    print("  D. Application exception before response")
    print()
    print("CLASSIFICATION: NOT_DIAGNOSTIC — seal endpoint unreachable")
    print("ACTION: Check Railway dashboard → Logs for the request_id above")
    sys.exit(1)

elif s3 == 200:
    sigilmark_id = b3.get("sigilmark_id") or b3.get("id")
    schema = b3.get("schema")
    print(f"✅ SEAL SUCCEEDED")
    print(f"   sigilmark_id: {sigilmark_id}")
    print(f"   schema:       {schema}")
    print()

    # ── STEP 3: VERIFY (raw response only, no field translation) ─────────
    print("── Step 3: Verify (raw response — no field translation) ──")
    s4, b4, t4 = hit("POST", "/v1/vcb/sigilmark/verify", {"sigilmark": b3})
    print(f"HTTP:          {s4}")
    print(f"RESPONSE_TIME: {t4:.3f}s")
    print()
    print("COMPLETE RAW VERIFY RESPONSE:")
    print(json.dumps(b4, indent=2, default=str))
    print()
    print(f"All returned fields: {list(b4.keys())}")
    print(f"result:    {b4.get('result','NOT_IN_RESPONSE')}")
    print(f"failures:  {b4.get('failures','NOT_IN_RESPONSE')}")
    print(f"schema:    {b4.get('schema','NOT_IN_RESPONSE')}")
    print()

    # ── STEP 4: TAMPER TEST ───────────────────────────────────────────────
    print("── Step 4: Tamper test (mutate integrity_hash) ──")
    tampered = json.loads(json.dumps(b3, default=str))
    original_hash = tampered.get("integrity_hash","")
    if original_hash:
        tampered["integrity_hash"] = "0" * len(original_hash)
        mutated = f"integrity_hash zeroed (was {original_hash[:16]}...)"
    else:
        # Fallback — mutate sigilmark_id if no integrity_hash
        tampered["sigilmark_id"] = "FORGED-SM-000000000000"
        mutated = "sigilmark_id replaced"

    print(f"Mutation: {mutated}")
    s7, b7, t7 = hit("POST", "/v1/vcb/sigilmark/verify", {"sigilmark": tampered})
    print(f"HTTP:          {s7}")
    print(f"RESPONSE_TIME: {t7:.3f}s")
    print()
    print("COMPLETE RAW TAMPER VERIFY RESPONSE:")
    print(json.dumps(b7, indent=2, default=str))
    print()
    print(f"result:   {b7.get('result','NOT_IN_RESPONSE')}")
    print(f"failures: {b7.get('failures','NOT_IN_RESPONSE')}")

    # ── FINAL ─────────────────────────────────────────────────────────────
    print()
    print("="*68)
    print("DIAGNOSTIC SUMMARY")
    print("="*68)
    print(f"BUILD_ID:    {b_h.get('build_id','?')}")
    print(f"INSTANCE_ID: {b_h.get('instance_id','?')}")
    print()
    print(f"SEAL:     HTTP {s3} — {'PASS' if s3==200 else 'FAIL'}")
    print(f"VERIFY:   HTTP {s4} result={b4.get('result','?')} failures={b4.get('failures','?')}")
    print(f"TAMPER:   HTTP {s7} result={b7.get('result','?')} failures={b7.get('failures','?')}")
    print()
    print("PRODUCTION_CLAIM_ALLOWED: False")

else:
    print(f"❌ UNEXPECTED HTTP {s3}")
    print(f"   Response: {b3}")
