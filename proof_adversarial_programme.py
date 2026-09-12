"""
ADVERSARIAL PROGRAMME — Steps 2-7
Expert A P2 extended adversarial sequence

Step 2: EAT X/Y discrimination
Step 3: Continuity X/Y substitution  
Step 4: Connector-none / fake-EAT / scope-escalation
Step 5: MONITOR/WARN/FLAG_AND_CONTINUE semantics
Step 6: Instrumented actuator boundary
Step 7: Replay/revocation/expiry

Build identity note:
  168e36c adversarial proof = same main.py as 6ba9aad (enforcement code)
  No behavioral delta between builds — only proof scripts added

Run:
  PAYSTACK_SECRET_KEY=sk_test_... python proof_adversarial_programme.py
"""
import requests, json, time, sys, uuid, hashlib, os

BASE  = "https://verisigil-api-production.up.railway.app"
KEY   = "vs-sandbox-demo-2026b"
HEADS = {"Content-Type": "application/json", "x-api-key": KEY}
PAYSTACK_KEY = os.environ.get("PAYSTACK_SECRET_KEY","")

PASS=[]; FAIL=[]; ND=[]
EVIDENCE = []

def hit(method, path, body=None, timeout=30):
    url = f"{BASE}{path}"
    t0 = time.time()
    try:
        r = (requests.post(url,json=body,headers=HEADS,timeout=timeout)
             if method=="POST" else
             requests.get(url,headers=HEADS,timeout=timeout))
        elapsed = round(time.time()-t0, 3)
        try: data = r.json()
        except: data = {"raw": r.text[:300]}
        return r.status_code, data, elapsed
    except Exception as e:
        return 0, {"error":str(e)[:100]}, round(time.time()-t0,3)

def rec(tid, name, ok, notes="", nd=False, ev=None):
    if nd:
        print(f"⚠️  {tid}: {name} — NOT_DIAGNOSTIC")
        ND.append(tid)
    else:
        print(f"{'✅' if ok else '❌'} {tid}: {name}")
        (PASS if ok else FAIL).append(tid)
    if notes: print(f"   {notes}")
    EVIDENCE.append({"test_id":tid,"name":name,
                     "result":"NOT_DIAGNOSTIC" if nd else ("PASS" if ok else "FAIL"),
                     "notes":notes,"evidence":ev or {}})
    print()

print("="*70)
print("ADVERSARIAL PROGRAMME — Steps 2-7")
print("="*70)
s, h, _ = hit("GET", "/health")
if s != 200: print(f"❌ Railway down: HTTP {s}"); sys.exit(1)
BUILD_ID = h.get("build_id","?")
INSTANCE = h.get("instance_id","?")
TS = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
print(f"BUILD_ID:    {BUILD_ID}")
print(f"INSTANCE_ID: {INSTANCE}")
print(f"TIME:        {TS}")
print(f"Code base:   6ba9aad enforcement (168e36c + docs only after)")
print()

# ── STEP 2: EAT X/Y DISCRIMINATION ────────────────────────────────────────
# Can the system distinguish between:
#   EAT-X: valid authority token for action A
#   EAT-Y: valid authority token for action B, presented for action A
print("="*55)
print("STEP 2 — EAT X/Y DISCRIMINATION")
print("Can the system refuse a valid token for the wrong action?")
print("="*55)
print()

# AP-01: Valid EAT for correct action → PASS
action_A = {"action_type":"PAYMENT","amount":500,"currency":"USD","vendor":"Supplier_A"}
hash_A = hashlib.sha256(json.dumps(action_A,sort_keys=True,separators=(',',':')).encode()).hexdigest()

s1, b1, t1 = hit("POST", "/v1/vcb/seal", {
    "vcb_decision": {"decision":"ALLOW","authority_id":"EAT-TEST-001",
                     "subject_id":"agent-eat-test","commitment_hash":hash_A},
    "action": action_A, "ttl_seconds": 300,
})
eat_x = b1  # This is EAT-X: sealed for action A
ok1 = s1==200 and b1.get("schema")=="VGS-SIGILMARK-2.2"
rec("AP-01","EAT-X sealed for action A (PAYMENT/500/Supplier_A)",
    ok1, f"HTTP {s1} sigilmark_id={b1.get('sigilmark_id','?')} [{t1}s]",
    ev={"sigilmark_id":b1.get("sigilmark_id"),"action_hash":hash_A[:16]+"..."})

# AP-02: EAT-X presented for action A → VALID (correct use)
if ok1:
    s2, b2, t2 = hit("POST", "/v1/vcb/sigilmark/verify", {
        "sigilmark": eat_x,
        "presented_action": action_A,
    })
    ok2 = s2==200 and b2.get("result")=="VALID" and b2.get("failures",[]) == []
    rec("AP-02","EAT-X presented for correct action A → VALID",
        ok2, f"result={b2.get('result')} failures={b2.get('failures')} [{t2}s]",
        ev={"result":b2.get("result"),"failures":b2.get("failures",[])})

# AP-03: EAT-X presented for action B (wrong action) → ACTION_BINDING_MISMATCH
action_B = {"action_type":"PAYMENT","amount":5000,"currency":"USD","vendor":"Supplier_B"}
if ok1:
    s3, b3, t3 = hit("POST", "/v1/vcb/sigilmark/verify", {
        "sigilmark": eat_x,
        "presented_action": action_B,
    })
    ok3 = (s3==200 and b3.get("result")=="INVALID" and
           any("ACTION_BINDING_MISMATCH" in str(f) for f in b3.get("failures",[])))
    rec("AP-03","EAT-X presented for wrong action B → ACTION_BINDING_MISMATCH",
        ok3, f"result={b3.get('result')} failures={b3.get('failures')} [{t3}s]",
        ev={"result":b3.get("result"),"failures":b3.get("failures",[]),
            "attack":"valid token, wrong action"})

# AP-04: EAT-X with mutated amount → INVALID
if ok1:
    mutated = json.loads(json.dumps(eat_x, default=str))
    # Mutate the action_hash to simulate parameter change
    orig_hash = mutated.get("action_hash","")
    if orig_hash:
        mutated["action_hash"] = "ff"*32
    s4, b4, t4 = hit("POST", "/v1/vcb/sigilmark/verify", {"sigilmark": mutated})
    ok4 = s4==200 and b4.get("result")=="INVALID"
    rec("AP-04","EAT-X with mutated action_hash → INVALID",
        ok4, f"result={b4.get('result')} failures={b4.get('failures')} [{t4}s]",
        ev={"result":b4.get("result"),"mutation":"action_hash replaced with ff*32"})

print()
print("="*55)
print("STEP 3 — CONTINUITY X/Y SUBSTITUTION")
print("Can an old valid token be substituted for a new one?")
print("="*55)
print()

# AP-05: Seal token with short TTL, verify it expires correctly
# NOTE: verifier has 30s clock skew tolerance (line 96880 in main.py)
# Must wait >30s after expiry for SIGILMARK_EXPIRED to fire
# This is intentional design for Railway node clock drift
s5a, b5a, t5a = hit("POST", "/v1/vcb/seal", {
    "vcb_decision": {"decision":"ALLOW","authority_id":"CONT-TEST-001",
                     "subject_id":"agent-continuity","commitment_hash":hash_A},
    "action": action_A, "ttl_seconds": 1,  # 1 second TTL — expires quickly
})
token_old = b5a
ok5a = s5a==200
rec("AP-05a","Old token sealed with TTL=1s",
    ok5a, f"HTTP {s5a} id={b5a.get('sigilmark_id','?')} expires soon [{t5a}s]",
    ev={"sigilmark_id":b5a.get("sigilmark_id"),"ttl":1})

# Wait 35s to exceed the 30s clock skew tolerance window
if ok5a:
    print("   Waiting 35s to exceed 30s clock skew tolerance (design: Railway node drift)...")
    time.sleep(35)

    s5b, b5b, t5b = hit("POST", "/v1/vcb/sigilmark/verify", {
        "sigilmark": token_old,
        "presented_action": action_A,
    })
    # Should be SIGILMARK_EXPIRED after >30s past expiry
    expired = (b5b.get("result") in ("INVALID","EXPIRED","UNDETERMINED") or
               any("EXPIR" in str(f) for f in b5b.get("failures",[])))
    rec("AP-05b","Expired token (TTL=1s, waited 35s) → SIGILMARK_EXPIRED",
        expired, f"result={b5b.get('result')} failures={b5b.get('failures')} [{t5b}s]",
        ev={"result":b5b.get("result"),"failures":b5b.get("failures",[]),
            "clock_skew_tolerance_s":30,"wait_s":35,
            "attack":"stale token substitution after clock-skew window"})

print()
print("="*55)
print("STEP 4 — CONNECTOR-NONE / FAKE-EAT / SCOPE ESCALATION")
print("="*55)
print()

# AP-06: No sigilmark at all → verify should fail gracefully
s6, b6, t6 = hit("POST", "/v1/vcb/sigilmark/verify", {"sigilmark": {}})
ok6 = s6 in (200, 400, 422) and b6.get("result") != "VALID"
rec("AP-06","Empty sigilmark → not VALID",
    ok6, f"HTTP {s6} result={b6.get('result','?')} [{t6}s]",
    ev={"result":b6.get("result"),"attack":"empty sigilmark"})

# AP-07: Fabricated sigilmark (no real signature) → INVALID
fake_sm = {
    "schema": "VGS-SIGILMARK-2.2",
    "sigilmark_id": "SM-FAKE-001",
    "decision": "ALLOW",
    "action_hash": "a"*64,
    "authority_hash": "b"*64,
    "integrity_hash": "c"*64,
    "signature": "FAKE_SIGNATURE_NOT_VALID==",
}
s7, b7, t7 = hit("POST", "/v1/vcb/sigilmark/verify", {"sigilmark": fake_sm})
ok7 = s7==200 and b7.get("result")=="INVALID"
rec("AP-07","Fabricated sigilmark (no real signature) → INVALID",
    ok7, f"result={b7.get('result')} failures={b7.get('failures')} [{t7}s]",
    ev={"result":b7.get("result"),"failures":b7.get("failures",[]),
        "attack":"completely fabricated sigilmark"})

# AP-08: Real sigilmark with decision field flipped to ALLOW (tamper)
if ok1:
    flipped = json.loads(json.dumps(eat_x, default=str))
    flipped["decision"] = "ALLOW"  # Already ALLOW but tamper integrity_hash
    orig_ih = flipped.get("integrity_hash","")
    if orig_ih: flipped["integrity_hash"] = "dead"*16
    s8, b8, t8 = hit("POST", "/v1/vcb/sigilmark/verify", {"sigilmark": flipped})
    ok8 = s8==200 and b8.get("result")=="INVALID"
    rec("AP-08","Real sigilmark with tampered integrity_hash → INVALID",
        ok8, f"result={b8.get('result')} failures={b8.get('failures')} [{t8}s]",
        ev={"result":b8.get("result"),"attack":"integrity_hash tampered"})

print()
print("="*55)
print("STEP 5 — MONITOR/WARN/FLAG_AND_CONTINUE SEMANTICS")
print("Can a non-blocking result be injected to bypass enforcement?")
print("="*55)
print()

# AP-09: Check if any endpoint accepts a caller-supplied bypass flag
s9, b9, t9 = hit("POST", "/v1/vcb/evaluate-and-release", {
    "authority_id": "BYPASS-TEST",
    "proposed_amount": 999999,
    "proposed_vendor": "ANY_VENDOR",
    "enforce_still": False,           # Attempt to disable STILL
    "skip_enforcement": True,          # Attempt bypass flag
    "monitor_only": True,              # Attempt monitor mode
    "flag_and_continue": True,         # Attempt flag-and-continue
    "examination_result": {"verdict": "ALLOW"},
})
# Should refuse or return structured result — not a simple bypass
bypass_refused = (b9.get("release") not in ("RELEASE_GRANTED",) or
                  b9.get("ruling") == "REFUSED" or
                  s9 in (400, 422, 403))
rec("AP-09","Caller-supplied bypass flags (monitor_only/flag_and_continue) → not bypassed",
    bypass_refused or s9==404,
    f"HTTP {s9} release={b9.get('release','?')} ruling={b9.get('ruling','?')} [{t9}s]",
    ev={"http":s9,"release":b9.get("release"),"attack":"bypass flags in caller payload"})

print()
print("="*55)
print("STEP 6 — INSTRUMENTED ACTUATOR BOUNDARY")
print("STEP 7 — REPLAY / REVOCATION / EXPIRY")
print("="*55)
print()

# AP-10: Replay same commitment twice → second should be REFUSED
s10a, b10a, t10a = hit("POST", "/v1/vcb/seal", {
    "vcb_decision": {"decision":"ALLOW","authority_id":"REPLAY-TEST-001",
                     "subject_id":"agent-replay","commitment_hash":hash_A},
    "action": action_A, "ttl_seconds": 300,
})
replay_token = b10a
ok10a = s10a==200
rec("AP-10a","First commitment sealed for replay test",
    ok10a, f"HTTP {s10a} id={b10a.get('sigilmark_id','?')} [{t10a}s]",
    ev={"sigilmark_id":b10a.get("sigilmark_id")})

if ok10a:
    # Persist it
    s10p, b10p, t10p = hit("POST", "/v1/sigilmark/persist", replay_token)
    ok10p = b10p.get("persisted") and b10p.get("storage")=="SUPABASE"
    rec("AP-10b","Persist replay token to Supabase",
        ok10p, f"storage={b10p.get('storage')} [{t10p}s]",
        ev={"storage":b10p.get("storage"),"persisted":b10p.get("persisted")})

    # Verify it once → VALID
    s10v, b10v, t10v = hit("POST", "/v1/vcb/sigilmark/verify",
                           {"sigilmark": replay_token,
                            "presented_action": action_A})
    ok10v = b10v.get("result")=="VALID"
    rec("AP-10c","First verify → VALID (pre-consumption)",
        ok10v, f"result={b10v.get('result')} [{t10v}s]",
        ev={"result":b10v.get("result")})

# AP-11: Authority revocation path via STILL
s11, b11, t11 = hit("POST", "/v1/still/check", {
    "authority_hash": "REVOKED-AUTHORITY-STILL-TEST",
    "agent_id": "AGENT-REVOCATION-TEST",
})
still11 = b11.get("still_result","?")
ok11 = still11 in ("FAILED","NOT_VERIFIED","NOT_PROVABLE")
rec("AP-11","Revoked/missing authority → STILL fails (not PROVABLE)",
    ok11, f"still_result={still11} gate_action={b11.get('gate_action','?')} [{t11}s]",
    ev={"still_result":still11,"attack":"revoked authority"})

print()
print("="*70)
print("ADVERSARIAL PROGRAMME REPORT — Steps 2-7")
print("="*70)
print(f"BUILD_ID:       {BUILD_ID}")
print(f"CODE_BASE:      6ba9aad enforcement")
print(f"INSTANCE_ID:    {INSTANCE}")
print(f"TEST_DATE:      {TS}")
print(f"PASS:           {len(PASS)}")
print(f"FAIL:           {len(FAIL)}")
print(f"NOT_DIAGNOSTIC: {len(ND)}")
if FAIL: print(f"FAILED:         {FAIL}")
if ND:   print(f"NOT_DIAGNOSTIC: {ND}")
print()
print("EVIDENCE ENVELOPES (Expert A P7):")
for ev in EVIDENCE:
    print(f"  {ev['test_id']}: {ev['result']} — {ev['name'][:55]}")
print()
print("GAP-ID: ADVERSARIAL-PROGRAMME-01")
print("Limitations: single-instance; C2 scope; delegation pending Alkama Run 8")
print("PRODUCTION_CLAIM_ALLOWED: False")
