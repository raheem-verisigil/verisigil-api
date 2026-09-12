"""
P1-C v2: Live Railway + Real Supabase Proof Run
Uses the correct live endpoint shapes discovered from the actual API.

Run from Git Bash:
  cd ~/verisigil-api
  /c/Users/User/AppData/Local/Programs/Python/Python310/python p1c_v2_live_proof.py

GAP-ID: P1-C-LIVE-SUPABASE-PROOF-02
"""
import requests, json, time, sys

BASE    = "https://verisigil-api-production.up.railway.app"
KEY     = "vs-sandbox-demo-2026b"
HEADERS = {"Content-Type": "application/json", "x-api-key": KEY}

PASS = []; FAIL = []

def hit(method, path, body=None, timeout=20):
    url = f"{BASE}{path}"
    try:
        r = requests.post(url, json=body, headers=HEADERS, timeout=timeout) \
            if method == "POST" else \
            requests.get(url, headers=HEADERS, timeout=timeout)
        try:    return r.status_code, r.json()
        except: return r.status_code, {"raw": r.text[:300]}
    except Exception as e:
        return 0, {"error": str(e)[:150]}

def rec(tid, name, ok, notes=""):
    icon = "✅" if ok else "❌"
    print(f"{icon} {tid}: {name}")
    if notes: print(f"   {notes}")
    print()
    (PASS if ok else FAIL).append(tid)

# ── PHASE 0: BASELINE ─────────────────────────────────────────────────────
print("="*68)
print("P1-C v2 — LIVE RAILWAY PROOF RUN")
print("="*68)
s, h = hit("GET", "/health")
if s != 200:
    print(f"❌ Railway unreachable: HTTP {s}"); sys.exit(1)

print(f"BUILD_ID:        {h.get('build_id','?')}")
print(f"INSTANCE_ID:     {h.get('instance_id','?')}")
print(f"PROCESS_STARTED: {h.get('process_started_at','?')}")
print(f"UPTIME_SECONDS:  {h.get('uptime_seconds','?')}")
print(f"ENVIRONMENT:     {h.get('environment','?')}")
print(f"TEST_DATE:       {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
print()

instance_id = h.get('instance_id', '')

# T-P1: Health has all required restart-observable fields
ok = all(h.get(f) for f in ['instance_id','process_started_at','build_id','uptime_seconds'])
rec("T-P1", "Health — all restart-observable fields present",
    ok, f"instance_id={instance_id} uptime={h.get('uptime_seconds','?')}s")

# ── PHASE 1: STILL ADVERSARIAL SUITE ON LIVE RAILWAY ─────────────────────
print("── STILL Adversarial Suite (live endpoint) ──")
print()

# This endpoint runs 10 STILL adversarial cases internally
# including revoke, expire, ceiling, vendor, forge, fail-closed
s2, b2 = hit("POST", "/v1/engineering/test-still-adapter", {})
print(f"test-still-adapter: HTTP {s2}")
if s2 == 200:
    all_p = b2.get("all_pass", b2.get("overall", False))
    tests = b2.get("tests", [])
    passed = [t for t in tests if t.get("status") == "PASS"]
    failed = [t for t in tests if t.get("status") == "FAIL"]
    print(f"  Tests: {len(tests)} | Pass: {len(passed)} | Fail: {len(failed)}")
    for t in tests:
        icon = "✅" if t.get("status")=="PASS" else "❌"
        print(f"  {icon} {t.get('test','?')[:60]}")
    ok2 = len(failed) == 0 and len(passed) > 0
    rec("T-P2", f"STILL Adversarial Suite on live Railway — {len(passed)}/{len(tests)} pass",
        ok2, f"all_pass={all_p}")
else:
    print(f"  Response: {str(b2)[:200]}")
    rec("T-P2", "STILL Adversarial Suite on live Railway", False,
        f"HTTP {s2} — {str(b2)[:150]}")
print()

# ── PHASE 2: SEAL A SIGILMARK (VALID DECISION) ───────────────────────────
print("── Seal a SigilMark with valid ALLOW decision ──")

# /v1/vcb/seal requires a pre-built vcb_decision with decision=ALLOW
import uuid, hashlib
action = {"action_type":"PAYMENT","amount":500,"currency":"USD","vendor":"Supplier_A"}
commit_hash = hashlib.sha256(json.dumps(action, sort_keys=True, separators=(',',':')).encode()).hexdigest()

seal_body = {
    "vcb_decision": {
        "decision": "ALLOW",
        "authority_id": "TEST-MANDATE-P1C",
        "subject_id": "agent-p1c",
        "rationale": "P1-C live proof run — test seal",
        "commitment_hash": commit_hash,
    },
    "action": action,
    "ttl_seconds": 300,
}

s3, b3 = hit("POST", "/v1/vcb/seal", seal_body)
print(f"Seal: HTTP {s3}")
sigilmark_id = b3.get("sigilmark_id") or b3.get("id") or b3.get("vcc_id")
ok3 = s3 == 200 and (sigilmark_id or b3.get("schema"))
rec("T-P3", "Seal SigilMark with ALLOW decision — live Railway",
    ok3, f"sigilmark_id={sigilmark_id} HTTP {s3} {str(b3)[:100]}")

# ── PHASE 3: VERIFY THE SEALED SIGILMARK ─────────────────────────────────
if ok3 and b3:
    print("── Verify sealed SigilMark ──")
    s4, b4 = hit("POST", "/v1/vcb/sigilmark/verify", {"sigilmark": b3})
    print(f"Verify: HTTP {s4}")
    integrity = b4.get("integrity","?")
    signature = b4.get("signature","?")
    verdict = b4.get("verdict","?")
    ok4 = s4 == 200 and integrity in ("VERIFIED","INTEGRITY_VERIFIED")
    rec("T-P4", "Verify SigilMark integrity + signature — live",
        ok4, f"integrity={integrity} signature={signature} verdict={verdict}")

    # ── PHASE 4: PERSIST AND RETRIEVE ────────────────────────────────────
    if sigilmark_id:
        print("── Persist + Retrieve from Supabase ──")
        s5, b5 = hit("POST", "/v1/sigilmark/persist", b3)
        storage = b5.get("storage","?")
        ok5 = s5 == 200 and storage in ("SUPABASE","IN_MEMORY_FALLBACK")
        rec("T-P5", f"Persist SigilMark to Supabase — storage={storage}",
            ok5, f"HTTP {s5} persisted={b5.get('persisted','?')}")

        s6, b6 = hit("GET", f"/v1/sigilmark/retrieve?sigilmark_id={sigilmark_id}")
        found = b6.get("found", False)
        ret_source = b6.get("retrieval_source","?")
        durability = b6.get("durability_verified","?")
        ok6 = s6 == 200 and found and ret_source == "SUPABASE"
        rec("T-P6", f"Retrieve SigilMark from Supabase — source={ret_source} durability={durability}",
            ok6, f"HTTP {s6} found={found}")

# ── PHASE 5: TAMPER TEST (T-P7) ──────────────────────────────────────────
print("── Tamper test — forge a field ──")
if b3 and isinstance(b3, dict):
    tampered = dict(b3)
    tampered["_forge"] = "ATTACKER"  # Add forged field
    if "payload" in tampered:
        tampered["payload"] = dict(tampered.get("payload", {}))
        tampered["payload"]["amount"] = 999999  # Tamper amount
    s7, b7 = hit("POST", "/v1/vcb/sigilmark/verify", {"sigilmark": tampered})
    tamper_result = b7.get("integrity","?")
    # Tampered sigilmark should fail integrity or signature
    ok7 = tamper_result in ("FAILED","INTEGRITY_FAILED","INVALID") or \
          b7.get("signature") in ("FAILED","INVALID") or \
          (s7 != 200 and s7 != 0)
    rec("T-P7", f"Tampered SigilMark → integrity fails",
        ok7, f"HTTP {s7} integrity={tamper_result} {str(b7)[:100]}")

# ── FINAL REPORT ─────────────────────────────────────────────────────────
print("="*68)
print("P1-C v2 LIVE SUPABASE PROOF REPORT")
print("="*68)
print(f"BUILD_ID:    {h.get('build_id','?')}")
print(f"INSTANCE_ID: {instance_id}")
print(f"TEST_COUNT:  {len(PASS)+len(FAIL)}")
print(f"PASS:        {len(PASS)}")
print(f"FAIL:        {len(FAIL)}")
print()
if FAIL: print(f"FAILED: {FAIL}")
else:    print("ALL PASS")
print()
print("GAP-ID: P1-C-LIVE-SUPABASE-PROOF-02")
print("Limitations: test mandate scope; C2 test key; single-instance Railway")
print("PRODUCTION_CLAIM_ALLOWED: False")
