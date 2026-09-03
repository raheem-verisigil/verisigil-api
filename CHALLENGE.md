# VeriSigil Challenge Protocol

**Version:** 1.0  
**Date:** 2026-09-03  
**Status:** Open — adversarial testing invited

---

## What This Is

We are building an execution boundary verification system for AI-governed consequential actions. We are publicly disclosing what we have proven and what we have not, and we are inviting independent adversarial testing.

If you find a failure on a path we claim is defended, we want to know.

---

## What We Claim (Current Scope)

Under tested conditions on a live production endpoint with real Supabase:

1. Revoked, expired, ceiling-exceeded, unauthorized-vendor, forged-STILL, and unknown authority mandates are refused before consequence
2. A tampered receipt returns INTEGRITY_HASH_INVALID
3. Inadmissible paths do not reach the Paystack actuator (state_mutation=NONE)
4. A consequence commitment with mutated parameters is rejected at the actuator boundary
5. Replay of a consumed commitment is refused

The full evidence is in VERISIGIL_PROOF_REPORT_V1.md

---

## Challenge Procedure

**Step 1 — State your test**

Before running, publish:
- The control you intend to test
- The attack vector you are using
- What you expect to happen if the system works correctly

**Step 2 — Run against the live endpoint**

```
https://verisigil-api-production.up.railway.app
```

API key for testing: `vs-sandbox-demo-2026b`

**Step 3 — Report the raw result**

Report exactly what you observed. Do not filter or interpret. If you received an unexpected result, include the full HTTP response.

**Step 4 — Classify your result**

- **PASS** — the control behaved as claimed
- **FAIL** — the control did not behave as claimed (a confirmed defect)
- **NOT_DIAGNOSTIC** — your test did not reach the control being tested (report this separately; it may indicate a harness issue, not a security failure)
- **NEW_FINDING** — you found a gap we did not claim to have closed

---

## What We Commit To

- Publish your finding exactly as reported
- Respond within one working day
- Fix confirmed defects on the live build
- Credit you by name in our evidence record
- Not reframe a failure as a limitation we already knew about

---

## What Is Out of Scope

These are gaps we have already declared and are not yet claiming:

- Multi-instance distributed atomicity (F-31)
- Webhook retry idempotency (F-34)
- Production actuator with live money (C2 scope only)
- Full 1,286 endpoint coverage
- Regulatory certification of any kind

Testing these and confirming they are not proven is welcome but will not be classified as a new finding — we already know.

---

## Offline Verification

To verify a SigilMark receipt independently without calling our API:

```bash
pip install jar-verify
jar_verify --receipt <receipt.json> --key lJWG0Wabt6uATPu5Upo6UEHWGXQqMyi6LMKQC0xwpY8=
```

Expected result when conditions cannot be re-established offline:
```
ISSUANCE INTEGRITY: VERIFIED
CURRENT STANDING: NOT_RE-ESTABLISHED
VERDICT: UNDETERMINED
```

UNDETERMINED is the correct behavior. The verifier does not invent authority.

---

*VeriSigil AI | scoped evidence for a consequence boundary*
