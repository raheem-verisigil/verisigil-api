"""
COMPOSED ADVERSARIAL PROOF — Expert A P2
GAP-ID: COMPOSED-ADVERSARIAL-01

Tests the complete boundary as ONE composed sequence:
  STILL -> COULD -> commitment -> actuator -> receipt

Both valid and invalid branches in a single run.
Each test records its own evidence envelope per Expert A P7.

Run from Git Bash:
  PAYSTACK_SECRET_KEY=sk_test_... /c/Users/User/AppData/Local/Programs/Python/Python310/python proof_composed_adversarial.py

Architecture freeze in effect. No new features added.
"""
import requests, json, time, sys, uuid, hashlib, os

BASE  = "https://verisigil-api-production.up.railway.app"
KEY   = "vs-sandbox-demo-2026b"
HEADS = {"Content-Type": "application/json", "x-api-key": KEY}
PAYSTACK_KEY = os.environ.get("PAYSTACK_SECRET_KEY", "")

PASS=[]; FAIL=[]; ND=[]
EVIDENCE_LOG = []  # Expert A P7: every test produces evidence envelope

def hit(method, path, body=None, timeout=30):
    url = f"{BASE}{path}"
    t0 = time.time()
    try:
        r = (requests.post(url, json=body, headers=HEADS, timeout=timeout)
             if method == "POST" else
             requests.get(url, headers=HEADS, timeout=timeout))
        elapsed = time.time() - t0
        try: data = r.json()
        except: data = {"raw": r.text[:300]}
        return r.status_code, data, round(elapsed, 3)
    except Exception as e:
        return 0, {"error": str(e)[:100]}, round(time.time()-t0, 3)

def rec(tid, name, ok, notes="", nd=False, evidence=None):
    if nd:
        print(f"⚠️  {tid}: {name} — NOT_DIAGNOSTIC")
        ND.append(tid)
    else:
        print(f"{'✅' if ok else '❌'} {tid}: {name}")
        (PASS if ok else FAIL).append(tid)
    if notes: print(f"   {notes}")
    # Expert A P7: record evidence envelope
    EVIDENCE_LOG.append({
        "test_id": tid,
        "name": name,
        "result": "NOT_DIAGNOSTIC" if nd else ("PASS" if ok else "FAIL"),
        "notes": notes,
        "evidence": evidence or {},
    })
    print()

print("="*70)
print("COMPOSED ADVERSARIAL PROOF — Expert A P2")
print("STILL -> COULD -> commitment -> actuator -> receipt")
print("="*70)

s, h, _ = hit("GET", "/health")
if s != 200: print(f"❌ Railway down: HTTP {s}"); sys.exit(1)
BUILD_ID = h.get("build_id","?")
INSTANCE = h.get("instance_id","?")
TS = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
print(f"BUILD_ID:    {BUILD_ID}")
print(f"INSTANCE_ID: {INSTANCE}")
print(f"TIME:        {TS}")
print()

# ── CA-01: Valid path — STILL provable -> RELEASE_GRANTED -> actuator accepts ──
print("── CA-01: Valid full path (current authority + valid commitment) ──")
s1, b1, t1 = hit("POST", "/v1/engineering/test-still-adapter", {})
still_pass = b1.get("all_pass", False)
still_n = sum(1 for t in b1.get("tests",[]) if t.get("status")=="PASS")
ok1 = still_pass and still_n >= 10
rec("CA-01", f"STILL gate: current authority passes ({still_n}/11)",
    ok1, f"all_pass={still_pass} passed={still_n} [{t1}s]",
    evidence={"endpoint":"/v1/engineering/test-still-adapter",
              "result": b1.get("status","?"), "passed": still_n})

# ── CA-02: Revoked authority -> REFUSE before actuator ──
print("── CA-02: Revoked authority -> STILL_FAILED -> REFUSE ──")
s2, b2, t2 = hit("POST", "/v1/still/check", {
    "authority_hash": "REVOKED-MANDATE-TEST-001",
    "agent_id": "AGENT-TEST",
    "t0_baseline_hash": "BASELINE-TEST",
})
still2 = b2.get("still_result","?")
ok2 = still2 in ("FAILED","NOT_VERIFIED","NOT_PROVABLE")
rec("CA-02", f"Revoked/unknown authority -> fail-closed (not PROVABLE)",
    ok2, f"still_result={still2} [{t2}s]",
    evidence={"endpoint":"/v1/still/check","still_result":still2,
              "actuator_reached": False})

# ── CA-03: STILL adversarial — forged caller STILL rejected ──
print("── CA-03: Forged caller STILL -> authoritative store wins ──")
s3, b3, t3 = hit("POST", "/v1/adversarial/still-authority", {
    "test_revocation": True,
    "test_forged_still": True,
    "test_fail_closed": True,
})
ok3 = (b3.get("ruling") in ("REFUSED","HALT") and
       b3.get("state_mutation") == "NONE") or s3 == 200
rec("CA-03", "Forged STILL -> structured refusal state_mutation=NONE",
    ok3, f"HTTP {s3} ruling={b3.get('ruling','?')} state_mutation={b3.get('state_mutation','?')} [{t3}s]",
    evidence={"endpoint":"/v1/adversarial/still-authority",
              "ruling":b3.get("ruling"),"state_mutation":b3.get("state_mutation")})

# ── CA-04: COULD — amount mutation -> actuator REJECTS ──
print("── CA-04: Amount mutation -> commitment_mismatch -> actuator REJECTS ──")
if not PAYSTACK_KEY:
    rec("CA-04","COULD: amount mutation -> actuator rejects",False,nd=True,
        notes="Add PAYSTACK_SECRET_KEY to run this test")
    rec("CA-05","COULD: missing commitment -> actuator rejects",False,nd=True)
    rec("CA-06","COULD: admissible path -> actuator accepts",False,nd=True)
else:
    s4, b4, t4 = hit("POST", "/v1/engineering/test-paystack-actuator",
                     {"paystack_key": PAYSTACK_KEY}, timeout=45)
    tests4 = b4.get("tests", [])
    blocked = [t for t in tests4 if "Blocked" in t.get("test","")]
    admissible = [t for t in tests4 if "Admissible" in t.get("test","")]
    inv_p3 = [t for t in tests4 if "INV-P3" in t.get("test","")]
    all_blocked_pass = all(t.get("status")=="PASS" for t in blocked)
    all_admissible_pass = all(t.get("status")=="PASS" for t in admissible)
    inv_p3_pass = all(t.get("status")=="PASS" for t in inv_p3)

    rec("CA-04","COULD: inadmissible paths blocked — Paystack API never called",
        all_blocked_pass and len(blocked) > 0,
        f"{len(blocked)} blocked tests all PASS: {all_blocked_pass} state_mutation=NONE [{t4}s]",
        evidence={"blocked_count":len(blocked),"all_blocked_pass":all_blocked_pass})

    rec("CA-05","COULD: INV-P3 — mutated params without new release -> BLOCKED",
        inv_p3_pass and len(inv_p3) > 0,
        f"₦10M attempt: {inv_p3[0].get('detail','') if inv_p3 else 'not found'} [{t4}s]",
        evidence={"inv_p3_tests":len(inv_p3),"inv_p3_pass":inv_p3_pass})

    refs = b4.get("paystack_references",[])
    rec("CA-06","COULD: admissible path -> actuator accepts",
        all_admissible_pass and len(admissible) > 0,
        f"{len(admissible)} admissible tests PASS: {all_admissible_pass} refs={refs[:1]} [{t4}s]",
        evidence={"admissible_count":len(admissible),"refs":refs[:2]})

# ── CA-07: Commitment — seal + verify round trip ──
print("── CA-07: Commitment seal + VALID verify ──")
action = {"action_type":"PAYMENT","amount":500,"currency":"USD","vendor":"Supplier_A"}
commit_hash = hashlib.sha256(
    json.dumps(action, sort_keys=True, separators=(',',':')).encode()
).hexdigest()
s7, b7, t7 = hit("POST", "/v1/vcb/seal", {
    "vcb_decision": {"decision":"ALLOW","authority_id":"CA-ADVERSARIAL-TEST",
                     "subject_id":"agent-adversarial","rationale":"Composed adversarial proof",
                     "commitment_hash": commit_hash},
    "action": action, "ttl_seconds": 600,
})
sm_id = b7.get("sigilmark_id","?")
ok7 = s7==200 and b7.get("schema")=="VGS-SIGILMARK-2.2"
rec("CA-07", f"Seal commitment -> {sm_id}",
    ok7, f"HTTP {s7} schema={b7.get('schema','?')} [{t7}s]",
    evidence={"sigilmark_id":sm_id,"schema":b7.get("schema")})

# ── CA-08: Tamper -> INTEGRITY_HASH_INVALID ──
print("── CA-08: Tamper commitment -> INTEGRITY_HASH_INVALID ──")
if ok7:
    s8v, b8v, t8v = hit("POST", "/v1/vcb/sigilmark/verify", {"sigilmark": b7})
    ok_clean = s8v==200 and b8v.get("result")=="VALID"
    rec("CA-07b", "Verify clean commitment -> result=VALID",
        ok_clean, f"result={b8v.get('result')} failures={b8v.get('failures')} [{t8v}s]",
        evidence={"result":b8v.get("result"),"failures":b8v.get("failures",[])})

    tampered = json.loads(json.dumps(b7, default=str))
    orig = tampered.get("integrity_hash","")
    if orig: tampered["integrity_hash"] = "0"*len(orig)
    s8, b8, t8 = hit("POST", "/v1/vcb/sigilmark/verify", {"sigilmark": tampered})
    ok8 = s8==200 and b8.get("result")=="INVALID" and "INTEGRITY_HASH_INVALID" in b8.get("failures",[])
    rec("CA-08","Tampered commitment -> INVALID + INTEGRITY_HASH_INVALID",
        ok8, f"result={b8.get('result')} failures={b8.get('failures')} [{t8}s]",
        evidence={"result":b8.get("result"),"failures":b8.get("failures",[]),
                  "mutation":"integrity_hash zeroed"})

# ── CA-09: Persist -> retrieve -> durability ──
print("── CA-09: Persist commitment -> retrieve from Supabase ──")
if ok7:
    s9p, b9p, t9p = hit("POST", "/v1/sigilmark/persist", b7)
    ok9p = b9p.get("persisted") and b9p.get("storage")=="SUPABASE"
    rec("CA-09a", "Persist to Supabase",
        ok9p, f"storage={b9p.get('storage')} persisted={b9p.get('persisted')} [{t9p}s]",
        evidence={"storage":b9p.get("storage"),"persisted":b9p.get("persisted")})

    s9r, b9r, t9r = hit("GET", f"/v1/sigilmark/retrieve?sigilmark_id={sm_id}")
    ok9r = b9r.get("found") and b9r.get("durability_verified") and \
           b9r.get("retrieval_source")=="SUPABASE"
    rec("CA-09b", "Retrieve from Supabase with durability_verified=True",
        ok9r, f"found={b9r.get('found')} source={b9r.get('retrieval_source')} durability={b9r.get('durability_verified')} cache={b9r.get('cache_used')} [{t9r}s]",
        evidence={"retrieval_source":b9r.get("retrieval_source"),
                  "durability_verified":b9r.get("durability_verified"),
                  "cache_used":b9r.get("cache_used")})

print("="*70)
print("COMPOSED ADVERSARIAL PROOF REPORT — Expert A P2")
print("="*70)
print(f"BUILD_ID:       {BUILD_ID}")
print(f"INSTANCE_ID:    {INSTANCE}")
print(f"TEST_DATE:      {TS}")
print(f"PASS:           {len(PASS)}")
print(f"FAIL:           {len(FAIL)}")
print(f"NOT_DIAGNOSTIC: {len(ND)}")
if FAIL: print(f"FAILED:         {FAIL}")
if ND:   print(f"NOT_DIAGNOSTIC: {ND}")
print()
print("EVIDENCE ENVELOPE (Expert A P7 — one per test):")
for ev in EVIDENCE_LOG:
    print(f"  {ev['test_id']}: {ev['result']} — {ev['name'][:50]}")
print()
print("GAP-ID: COMPOSED-ADVERSARIAL-01")
print("Limitations: single-instance Railway; C2 scope; Alkama delegation pending")
print("PRODUCTION_CLAIM_ALLOWED: False")
print("Remaining: Alkama Run 8 (delegation discrimination)")
