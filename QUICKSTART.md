# VCB jar-verify — External Portability Test

**10-minute guide. No prior context required.**

---

## What This Tests

You will verify that a passport issued by the VCB production API is:
- Cryptographically signed by the VCB signing key
- Integrity-protected (SHA-256 over RFC 8785 canonical form)
- Independently verifiable — no network access needed after the initial fetch

---

## Prerequisites

- Python 3.9+
- pip

```bash
pip install pynacl rfc8785
```

---

## Step 1 — Get the checker

```bash
git clone https://github.com/raheem-verisigil/verisigil-api.git
cd verisigil-api
```

Or download `jar_verify.py` directly from the repo.

---

## Step 2 — Get a fresh passport from production

```bash
curl -s -X POST https://verisigil-api-production.up.railway.app/v1/vcb/seal \
  -H "X-API-Key: verisigil-secret-2026" \
  -H "Content-Type: application/json" \
  -d '{
    "vcb_decision": {
      "decision": "ALLOW",
      "action_hash": "abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
      "authority_hash": "def456abc123def456abc123def456abc123def456abc123def456abc123def4",
      "policy_hash": "aaa111bbb222aaa111bbb222aaa111bbb222aaa111bbb222aaa111bbb222aaa1",
      "state_hash": "bbb222ccc333bbb222ccc333bbb222ccc333bbb222ccc333bbb222ccc333bbb2",
      "consequence_type": "PAYMENT"
    },
    "action": {"type": "payment", "amount": 5000, "vendor": "VENDOR-A"},
    "enforcement_point": "payment-boundary-v1",
    "ttl_seconds": 86400
  }' > passport.json
```

---

## Step 3 — Verify the passport

```bash
python jar_verify.py passport.json \
  --pubkey lJWG0Wabt6uATPu5Upo6UEHWGXQqMyi6LMKQC0xwpY8=
```

---

## Expected Result

```
============================================================
  jar-verify-0.2.0
============================================================
  VERDICT:    UNDETERMINED
  ROOT KIND:  ORGANIZATIONAL_FIAT
  ...
  Checks (14):
    ✓ schema_version: SCHEMA_V2.2: VGS-SIGILMARK-2.2
    ✓ integrity_hash: INTEGRITY_VERIFIED (rfc8785-jcs-v1)
    ✓ signature: SIGNATURE_VERIFIED (rfc8785-jcs-v1)
    ...
============================================================
```

**INTEGRITY_VERIFIED** and **SIGNATURE_VERIFIED** are the critical lines.

**VERDICT: UNDETERMINED** is correct and honest. The scope_ledger in the passport lists what was NOT examined (STILL not enforced, custody class GAP_UNKNOWN). The checker does not fail-open — it reports exactly what can and cannot be established.

---

## What the Exit Codes Mean

| Exit | Meaning |
|---|---|
| 0 | ADMISSIBLE — all conditions met |
| 1 | FAILED — definitive domain violation detected |
| 2 | UNDETERMINED — incomplete evidence (honest, expected for standard passports) |
| 3 | INVALID — structural integrity failure (tampered bytes) |
| 9 | REPLAY_UNAVAILABLE — replay digest mismatch |

---

## Conformance Vectors

To test the checker against adversarial inputs, see `conformance_vectors.json`. Each vector specifies a mutation and expected exit code.

---

## Public Key

```
lJWG0Wabt6uATPu5Upo6UEHWGXQqMyi6LMKQC0xwpY8=
```

Ed25519 (PyNaCl VerifyKey). Stable across restarts — derived deterministically from the signing secret.

---

## Trusted Computing Base

See `TCB.md` for the honest boundary: what VCB proves, what it does not prove, and where the proof stops.

---

*Issues? Open a GitHub issue or contact verisigil.ai*
