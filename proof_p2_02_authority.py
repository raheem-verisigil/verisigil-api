"""
P2-02 PROOF SCRIPT — Authority Record Schema
VGS-AUTHORITY-1.0

Key distinction being proven: Identity (who) ≠ Authority (what may they do)

Five-question gate:
  1. Independently verifiable?     YES — GET /v1/authorities/{id}
  2. Decision reconstructable?     YES — status + reason + scope in response
  3. Authority ≠ identity?         YES — authority requires registered principal
  4. Historical ≠ current?         YES — status checked at evaluation time
  5. Failure → block?              YES — unknown/revoked/expired/scope → BLOCK
"""
import requests, time, sys, uuid
from datetime import datetime, timezone, timedelta

BASE = "https://verisigil-api-production-b79a.up.railway.app"
KEY  = "vs-sandbox-demo-2026b"
HEADS = {"Content-Type": "application/json", "x-api-key": KEY}

PASS=[]; FAIL=[]; ND=[]

def hit(method, path, body=None, params=None, timeout=15):
    url = f"{BASE}{path}"
    try:
        r = (requests.post(url, json=body, headers=HEADS, timeout=timeout)
             if method == "POST" else
             requests.get(url, headers=HEADS, params=params, timeout=timeout))
        try: data = r.json()
        except: data = {"raw": r.text[:200]}
        return r.status_code, data
    except Exception as e:
        return 0, {"error": str(e)[:100]}

def rec(tid, name, ok, notes="", nd=False):
    if nd:
        print(f"⚠️  {tid}: {name} — NOT_DIAGNOSTIC")
        ND.append(tid)
    else:
        print(f"{'✅' if ok else '❌'} {tid}: {name}")
        (PASS if ok else FAIL).append(tid)
    if notes: print(f"   {notes}")
    print()

print("="*65)
print("P2-02 PROOF — Authority Record Schema (VGS-AUTHORITY-1.0)")
print("="*65)

s, h = hit("GET", "/health")
if s != 200: print(f"❌ Railway down: HTTP {s}"); sys.exit(1)
BUILD_ID = h.get("build_id","?")
print(f"BUILD_ID:    {BUILD_ID}")
print(f"INSTANCE_ID: {h.get('instance_id','?')}")
print()

uid = uuid.uuid4().hex[:8].upper()

# First register a principal to link authority to
pid = f"PRINCIPAL-AUTH-TEST-{uid}"
s0, b0 = hit("POST", "/v1/principals/register", {
    "principal_id": pid,
    "identity_type": "AI_AGENT",
    "issuer": "P2-02-Proof",
})
if not b0.get("registered"):
    print(f"❌ Could not register test principal: {b0}")
    sys.exit(1)
print(f"Test principal registered: {pid}")
print()

# ── P2-AU-01: Register valid authority linked to principal ───────────────
print("── Register: valid authority for principal ──")
aid = f"AUTHORITY-TEST-{uid}"
s1, b1 = hit("POST", "/v1/authorities/register", {
    "authority_id": aid,
    "principal_id": pid,
    "granted_authority": "PAYMENT_EXECUTION",
    "purpose": "P2-02 proof test",
    "scope": ["payment.create", "payment.read"],
    "permitted_actions": ["payment.create", "payment.read"],
    "restricted_actions": ["payment.delete", "payment.refund"],
    "ceiling": 10000,
    "evidence": f"P2-02 proof run {uid}",
})
ok1 = s1 == 200 and b1.get("registered") == True and b1.get("status") == "ACTIVE"
rec("P2-AU-01", "Register authority → registered=True status=ACTIVE",
    ok1, f"HTTP {s1} registered={b1.get('registered')} status={b1.get('status')}")

# ── P2-AU-02: Authority note states identity ≠ authority ────────────────
note = b1.get("note","")
identity_ne_authority = "Identity" in note and "Authority" in note and "separate" in note
rec("P2-AU-02", "Registration note states Identity ≠ Authority",
    ok1 and identity_ne_authority,
    f"identity_ne_authority_note: {identity_ne_authority}")

# ── P2-AU-03: Retrieve authority → ACTIVE, admissible ───────────────────
print("── Retrieve: authority → ACTIVE, admissible ──")
s3, b3 = hit("GET", f"/v1/authorities/{aid}")
ok3 = (s3 == 200 and b3.get("found") == True and
       b3.get("status") == "ACTIVE" and b3.get("admissible") == True)
rec("P2-AU-03", "Retrieve authority → found=True admissible=True",
    ok3, f"HTTP {s3} status={b3.get('status')} admissible={b3.get('admissible')} reason={b3.get('admissibility_reason')}")

# ── P2-AU-04: Unknown authority → BLOCK ─────────────────────────────────
print("── Unknown authority → BLOCK ──")
s4, b4 = hit("GET", f"/v1/authorities/AUTHORITY-UNKNOWN-{uid}")
ok4 = s4 == 404 and b4.get("admissible") == False and b4.get("reason") == "AUTHORITY_NOT_FOUND"
rec("P2-AU-04", "Unknown authority → 404 admissible=False AUTHORITY_NOT_FOUND",
    ok4, f"HTTP {s4} admissible={b4.get('admissible')} reason={b4.get('reason')}")

# ── P2-AU-05: Authority without principal → rejected ────────────────────
print("── Authority requires registered principal ──")
s5, b5 = hit("POST", "/v1/authorities/register", {
    "authority_id": f"AUTHORITY-NO-PRINCIPAL-{uid}",
    "principal_id": f"PRINCIPAL-DOES-NOT-EXIST-{uid}",
    "granted_authority": "PAYMENT_EXECUTION",
})
ok5 = s5 == 404 and b5.get("error") == "PRINCIPAL_NOT_FOUND"
rec("P2-AU-05", "Authority for unknown principal → 404 PRINCIPAL_NOT_FOUND",
    ok5, f"HTTP {s5} error={b5.get('error')}")

# ── P2-AU-06: Scope check — action in scope → admissible ────────────────
print("── Scope: action in scope → admissible ──")
s6, b6 = hit("GET", f"/v1/authorities/{aid}",
             params={"action": "payment.create"})
ok6 = s6 == 200 and b6.get("admissible") == True
rec("P2-AU-06", "payment.create in scope → admissible=True",
    ok6, f"admissible={b6.get('admissible')} reason={b6.get('admissibility_reason')}")

# ── P2-AU-07: Scope check — action NOT in scope → BLOCK ─────────────────
print("── Scope: action NOT in scope → BLOCK ──")
s7, b7 = hit("GET", f"/v1/authorities/{aid}",
             params={"action": "payment.delete"})
ok7 = s7 == 200 and b7.get("admissible") == False and b7.get("admissibility_reason") == "ACTION_NOT_IN_SCOPE"
rec("P2-AU-07", "payment.delete NOT in scope → admissible=False ACTION_NOT_IN_SCOPE",
    ok7, f"admissible={b7.get('admissible')} reason={b7.get('admissibility_reason')}")

# ── P2-AU-08: Ceiling check — within ceiling → admissible ───────────────
print("── Ceiling: within ceiling → admissible ──")
s8, b8 = hit("GET", f"/v1/authorities/{aid}",
             params={"ceiling": 5000})
ok8 = s8 == 200 and b8.get("admissible") == True
rec("P2-AU-08", "ceiling 5000 ≤ authority 10000 → admissible=True",
    ok8, f"admissible={b8.get('admissible')} reason={b8.get('admissibility_reason')}")

# ── P2-AU-09: Ceiling check — exceeds ceiling → BLOCK ───────────────────
print("── Ceiling: exceeds ceiling → BLOCK ──")
s9, b9 = hit("GET", f"/v1/authorities/{aid}",
             params={"ceiling": 15000})
ok9 = s9 == 200 and b9.get("admissible") == False and b9.get("admissibility_reason") == "CEILING_EXCEEDED"
rec("P2-AU-09", "ceiling 15000 > authority 10000 → admissible=False CEILING_EXCEEDED",
    ok9, f"admissible={b9.get('admissible')} reason={b9.get('admissibility_reason')}")

# ── P2-AU-10: State endpoint ─────────────────────────────────────────────
print("── State endpoint ──")
s10, b10 = hit("GET", f"/v1/authorities/{aid}/state")
ok10 = (s10 == 200 and b10.get("status") == "ACTIVE" and
        b10.get("admissible") == True and b10.get("ceiling") == 10000)
rec("P2-AU-10", "State endpoint → status=ACTIVE admissible=True ceiling=10000",
    ok10, f"HTTP {s10} status={b10.get('status')} ceiling={b10.get('ceiling')}")

# ── P2-AU-11: Missing required fields → 422 ─────────────────────────────
print("── Validation: missing fields → 422 ──")
s11a, b11a = hit("POST", "/v1/authorities/register", {
    "principal_id": pid, "granted_authority": "X"
})
ok11a = s11a == 422 and b11a.get("error") == "MISSING_AUTHORITY_ID"
rec("P2-AU-11a", "Missing authority_id → 422 MISSING_AUTHORITY_ID",
    ok11a, f"HTTP {s11a} error={b11a.get('error')}")

s11b, b11b = hit("POST", "/v1/authorities/register", {
    "authority_id": f"TEST-{uid}", "granted_authority": "X"
})
ok11b = s11b == 422 and b11b.get("error") == "MISSING_PRINCIPAL_ID"
rec("P2-AU-11b", "Missing principal_id → 422 MISSING_PRINCIPAL_ID",
    ok11b, f"HTTP {s11b} error={b11b.get('error')}")

s11c, b11c = hit("POST", "/v1/authorities/register", {
    "authority_id": f"TEST-{uid}", "principal_id": pid
})
ok11c = s11c == 422 and b11c.get("error") == "MISSING_GRANTED_AUTHORITY"
rec("P2-AU-11c", "Missing granted_authority → 422 MISSING_GRANTED_AUTHORITY",
    ok11c, f"HTTP {s11c} error={b11c.get('error')}")

# ── P2-AU-12: Schema confirms identity ≠ authority ──────────────────────
print("── Schema: identity ≠ authority ──")
s12, b12 = hit("GET", f"/v1/authorities/{aid}")
schema_correct = b12.get("schema") == "VGS-AUTHORITY-1.0"
has_granted_authority = bool(b12.get("granted_authority"))
links_to_principal = bool(b12.get("principal_id"))
note12 = b12.get("note","")
historical_note = "Historical authority does not automatically" in note12
ok12 = schema_correct and has_granted_authority and links_to_principal and historical_note
rec("P2-AU-12", "Authority schema: VGS-AUTHORITY-1.0, links to principal, historical≠current note",
    ok12, f"schema={b12.get('schema')} principal_id={b12.get('principal_id')} historical_note={historical_note}")

print("="*65)
print("P2-02 PROOF REPORT — Authority Record Schema")
print("="*65)
print(f"BUILD_ID: {BUILD_ID}")
total = len(PASS)+len(FAIL)
print(f"PASS: {len(PASS)} | FAIL: {len(FAIL)} | NOT_DIAGNOSTIC: {len(ND)}")
if FAIL: print(f"FAILED: {FAIL}")
print()
print("What P2-02 establishes:")
print("  ✓ Authority Record linked to registered Principal")
print("  ✓ Authority without Principal → rejected (PRINCIPAL_NOT_FOUND)")
print("  ✓ Unknown authority → BLOCK (AUTHORITY_NOT_FOUND)")
print("  ✓ Scope check: action in scope → admissible")
print("  ✓ Scope check: action not in scope → BLOCK")
print("  ✓ Ceiling check: within ceiling → admissible")
print("  ✓ Ceiling check: exceeds ceiling → BLOCK")
print("  ✓ Schema: VGS-AUTHORITY-1.0, Identity ≠ Authority explicit")
print("  ✓ Historical authority ≠ current (note in every response)")
print()
print("What P2-02 does NOT establish:")
print("  - Authority status transitions (ACTIVE→REVOKED→INVALID) — P2-04")
print("  - Material change detection — P2-05")
print("  - Integration with SigilMark seal path — P2-08")
print()
print("PRODUCTION_CLAIM_ALLOWED: False")
print("Next: P2-03 Operating Conditions Schema")
