# VeriSigil AI — Pilot Corridor Specification
## VS-CORRIDOR-01: Supplier Payment Consequence Boundary
## Version: v0.1 — August 2026
## Status: TESTBED — test actuator only, declared limitations below

---

## What this corridor tests

Before an AI agent is permitted to execute a supplier payment instruction,
VeriSigil re-establishes whether the required authority and conditions still
hold at the moment of commitment — and refuses when they cannot be established.

This is not logging. This is not post-hoc audit.
The refusal happens before the actuator is called.

---

## The governing question

> An agent proposes a $X supplier payment.
> The authority that approved this may have been valid at T0.
> Is it still valid right now, at Tn?

If yes: ALLOW — actuator called, signed evidence issued.
If no: REFUSE — actuator not called, refusal receipt issued.
If unknown: NOT_PROVABLE — actuator not called, uncertainty preserved.

---

## What you need to bring

```
1. A payment instruction to test:
   - amount (≤ declared ceiling)
   - vendor identifier
   - currency

2. An authority declaration:
   - who authorized the agent
   - what scope and ceiling applies
   - what policy version governs

3. Nothing else.
   VeriSigil does not require access to your systems.
   VeriSigil does not require your production credentials.
```

---

## What VeriSigil tests — in sequence

```
STEP 1 — WHY
  Is the proposed action grounded in a declared authority?
  Is the amount within the declared ceiling?
  Is the vendor within the declared scope?

STEP 2 — STILL
  Does the authority still hold right now?
  Has the mandate been revoked?
  Has the mandate expired?
  Is the authority source reachable?
  If any condition cannot be established: NOT_PROVABLE → REFUSE

STEP 3 — COULD
  Can the action reach the actuator through the governed path?
  Is replay protection active?
  Is the release token consumed atomically?

STEP 4 — WHAT
  If ALLOW: actuator called, signed evidence issued
  If REFUSE: actuator not called, refusal receipt issued
  If NOT_PROVABLE: actuator not called, uncertainty preserved
```

---

## What evidence you receive

```
VERIFICATION RECEIPT — signed, portable, independently verifiable

ISSUANCE INTEGRITY:       VERIFIED
CURRENT STANDING:         [ESTABLISHED | NOT_ESTABLISHED | NOT_PROVABLE]
CONSEQUENCE SUFFICIENCY:  [ESTABLISHED | NOT_ESTABLISHED | NOT_PROVABLE]
VERDICT:                  [ALLOW | REFUSE | NOT_PROVABLE]

REASON CODE:              [if REFUSE — exact reason]
EXPLICIT NON-CLAIMS:      [what this receipt does not prove]
INDEPENDENT VERIFICATION: jar_verify.py [exact command]
```

---

## What the receipt explicitly does NOT prove

```
- That current authority holds offline
  (CURRENT STANDING: NOT_RE-ESTABLISHED is correct for offline verification)

- That the system is non-bypassable
  (the audit covered the declared governed path — not all possible paths)

- That live money was tested
  (test actuator only — C2 permanent limitation until production proof)

- That owner-continuity is enforced
  (CAT-01 is the next named engineering test — not yet run)

- That delegation escalation is prevented on real persistent state
  (schema enforcement present — adversarial proof pending)
```

---

## One-command pilot

```bash
# Prerequisites: curl, Python 3, git

# 1. Clone the verifier
git clone https://github.com/raheem-verisigil/verisigil-api
cd verisigil-api

# 2. Test a valid action (should ALLOW)
curl -X POST https://verisigil-api-production.up.railway.app/v1/vcb/seal \
  -H "X-API-Key: verisigil-secret-2026" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "pilot-agent-001",
    "action_type": "PAYMENT_INSTRUCTION",
    "amount": 500,
    "currency": "USD",
    "vendor": "SUPPLIER_A",
    "release_id": "pilot-release-001"
  }' | python3 -m json.tool > vs_receipt_001.json

# 3. Verify offline — no internet required after this step
python3 jar_verify.py vs_receipt_001.json \
  --pubkey lJWG0Wabt6uATPu5Upo6UEHWGXQqMyi6LMKQC0xwpY8=

# 4. Test stale/revoked authority (should REFUSE)
curl -X POST https://verisigil-api-production.up.railway.app/v1/engineering/test-stale-receipt \
  -H "X-API-Key: verisigil-secret-2026" \
  -H "Content-Type: application/json" \
  -d '{"scenario": "REVOKED_AUTHORITY"}' | python3 -m json.tool

# 5. Test replay protection (should REFUSE second attempt)
curl -X POST https://verisigil-api-production.up.railway.app/v1/vcb/seal \
  -H "X-API-Key: verisigil-secret-2026" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "pilot-agent-001",
    "action_type": "PAYMENT_INSTRUCTION",
    "amount": 500,
    "currency": "USD",
    "vendor": "SUPPLIER_A",
    "release_id": "pilot-release-001"
  }' | python3 -m json.tool
# Expected: ALREADY_CONSUMED — replay blocked

# 6. Verify the verifier itself independently
python3 jar_verify.py --help
# Public key: lJWG0Wabt6uATPu5Upo6UEHWGXQqMyi6LMKQC0xwpY8=
```

---

## Test vectors included in this corridor

| Test ID | Scenario | Expected Result | Current Status |
|---|---|---|---|
| VS-TEST-001 | Valid action, valid authority | ALLOW, receipt issued | DEMONSTRATED |
| VS-TEST-002 | Stale/revoked authority | REFUSE, actuator not called | DEMONSTRATED 10/10 |
| VS-TEST-003 | Replay attempt | REFUSE, ALREADY_CONSUMED | DEMONSTRATED 6/6 |
| VS-TEST-004 | Amount exceeds ceiling | REFUSE, CEILING_EXCEEDED | DEMONSTRATED |
| VS-TEST-005 | Authority source unavailable | NOT_PROVABLE → REFUSE | IMPLEMENTED |
| CAT-01 | O1→O2 owner change, no reapproval | REFUSE or ESCALATE | NOT YET RUN |
| STILL-01 | Caller-forged authority state | REFUSE | NOT YET RUN |
| PROOF-06 | Parameter mutation after examination | COMMITMENT_MISMATCH | NOT YET BUILT |

---

## Known limitations — declared, not hidden

```
C2 PERMANENT:
  Test actuator only. No live money.
  Production actuator proof is a declared open engineering obligation.

OWNER-CONTINUITY NOT YET ENFORCED:
  CAT-01 (O1→O2 owner transfer) is the next named falsification test.
  If the current implementation does not detect owner-continuity loss,
  that will be reported as a gap, not treated as a pass.

STILL ADVERSARIAL SUITE PENDING:
  STILL-01 through STILL-08 defined but not yet run as a named suite.

DELEGATION ON PERSISTENT STATE PENDING:
  Schema enforcement present.
  Child-exceeds-parent adversarial proof pending.

CONSEQUENCECOMMITMENT NOT YET BUILT:
  Parameter binding between examined action and executed action
  is doctrine only — not enforced in the execution path.

AUDIT SCOPE:
  Zero ungoverned routes found in the audited inventory.
  This is not a claim of universal non-bypassability.
  Background jobs, webhooks, and service-role access
  require separate audit.
```

---

## What "independently verifiable" means in this corridor

Any practitioner with the public key and the verifier can:

```
✅ Confirm the receipt was cryptographically signed in the form presented
✅ Confirm a tampered field produces exit code 3 (INVALID)
✅ Confirm ISSUANCE INTEGRITY: VERIFIED
✅ Confirm CURRENT STANDING: NOT_RE-ESTABLISHED (offline — correct)
✅ Confirm the explicit non-claims are present

Cannot confirm offline:
❌ Whether authority was current at action time (requires live Supabase)
❌ Whether the actuator was truly not called (requires actuator log)
❌ Whether owner-continuity was enforced (CAT-01 pending)
```

---

## Pilot timeline

```
NOW:
  VS-TEST-001 through VS-TEST-005 — available immediately
  jar_verify.py — public, reproducible in <10 minutes

AFTER ALKAMA DP-3/DP-4:
  CAT-01 runs — result published pass or fail

AFTER STILL SUITE:
  STILL-01 through STILL-08 — named adversarial results published

AFTER CONSEQUENCECOMMITMENT:
  PROOF-06 closes — parameter binding enforced

AFTER ALL ABOVE:
  Full independent reproduction package — external reviewer takes it cold
  Then and only then: "pilotable with complete evidence"
```

---

## Contact

Design partner inquiry: info@verisigilai.com
Repository: github.com/raheem-verisigil/verisigil-api
Governance doctrine: doi.org/10.5281/zenodo.20627386

---

*VeriSigil AI — VS-CORRIDOR-01 Pilot Specification*
*August 2026 — Testbed scope — declared limitations apply*
*PRODUCTION_CLAIM_ALLOWED: False*
