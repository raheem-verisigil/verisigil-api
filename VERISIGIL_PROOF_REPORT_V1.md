# VeriSigil AI — Proof Report v1

**Date:** 2026-09-03  
**Build:** a986a9e6e99c71ea (Railway production)  
**Status:** PRODUCTION_CLAIM_ALLOWED = False | LOCKED_CLAIM = NOT_YET_DELIVERED  
**Invitation:** We invite adversarial testing. If you find a failure, we will publish it, fix it, and credit you.

---

## What This Is

This is not a certification. It is a dated, attributable baseline of what we have proven and what we have not, under defined conditions, with evidence levels and explicit limitations.

Every claim maps to a test. Every test has a named limitation. Nothing is implied beyond what the evidence shows.

---

## Section 1 — What Is Proven

### V5 — Independently cold-reproduced (external engineer, no guidance given)

**1. Receipt integrity + Ed25519 signature verified**  
An independent external engineer from OMNIX QUANTUM LTD ran jar-verify-0.2.0 against a production SigilMark without being told the expected result. INTEGRITY_VERIFIED and SIGNATURE_VERIFIED confirmed. 12/15 checks passed. 3 soft warnings were produced for conditions requiring live verification (STILL, custody, COULD) — consistent with declared scope.  
*Limitation: Offline only. Verification of the artifact is not the same as proving current authority for a live action.*

**2. UNDETERMINED is the correct behavior when live conditions cannot be re-established**  
The same cold run returned VERDICT: UNDETERMINED. The verifier did not invent authority where evidence was insufficient. This is the designed fail-closed posture confirmed externally.  
*Limitation: Offline artifact only. Does not constitute a live STILL check.*

**3. NOT_DIAGNOSTIC classification discipline**  
When an independent external test failed before reaching the control being tested (float-inf serialization error), the result was classified NOT_DIAGNOSTIC — not a security refusal. This is a public record.  
*Limitation: Discipline only. Not a security control.*

---

### V4 — Live Railway production endpoint + real Supabase, confirmed on multiple builds

**4. STILL adversarial suite 11/11 on live Supabase**  
POST /v1/engineering/test-still-adapter returned 11/11 PASS on live Railway with real Supabase. Revoked authority → STILL_FAILED. Expired authority → STILL_FAILED. Amount exceeds ceiling → STILL_FAILED. Unauthorized vendor → STILL_FAILED. Forged caller-supplied STILL_PROVABLE → authoritative store wins. Unknown mandate → STILL_NOT_PROVABLE (fail-closed). Confirmed on builds 0e9575012046ad3b and fdbd2e7b723d486c.  
*Limitation: Test mandate scope. Single-instance Railway.*

**5. Supabase persistence + retrieval with durability verified**  
SigilMark persisted to real Supabase: storage=SUPABASE, persisted=True. Retrieved: retrieval_source=SUPABASE, durability_verified=True, cache_used=False. Confirmed on two independent builds.  
*Limitation: Test mandate scope.*

**6. Tamper detection on live endpoint**  
Zeroed integrity_hash field on a valid SigilMark: result=INVALID, failures=[INTEGRITY_HASH_INVALID]. Confirmed on multiple runs across multiple builds.  
*Limitation: Single mutation type tested (integrity_hash zeroing).*

**7. Actuator boundary — inadmissible paths never reach Paystack API**  
6/6 Paystack actuator tests PASS on live Railway. Blocked paths: state_mutation=NONE, paystack_api_called=False. INV-P1 through INV-P5 satisfied. Admissible path reached the actuator boundary.  
*Limitation: Test mode. Placeholder key used — architecture boundary proven; no real Paystack reference produced in this run.*

**8. COULD binding — exact action parameters required**  
INV-P3: modified parameters (₦10M attempt) without a new release → BLOCKED, state_mutation=NONE. Admissible path executed. C-01, C-02, C-03 all PASS.  
*Limitation: Test mode. Single payment path.*

**9. Post-restart durability — independently confirmed**  
Independent external tester planted anchor SM-922E1C2CD7C0C71AF1EB before process_started_at. Retrieved post-restart with durability_verified=True, cache_used=False. Instance ID change confirmed restart.  
*Limitation: Single restart event. Single instance.*

**10. enforce_still=False reachability — 0 production consequence paths**  
Static call-graph audit: 58 occurrences in codebase. 21 are doctrine strings. 12 are live calls, all inside /v1/p4/ and /v1/engineering/ test routes. 0 reach any production consequence-capable path. Caller cannot inject enforce_still=False via HTTP.  
*Limitation: Static analysis. Runtime verification of every alternate path not done.*

---

### V3 — Internal adversarial (not independently reproduced externally for these items)

**11. Execution admissibility 17/18 in-memory scenarios**  
T-01 through T-18: REFUSE on stale, mutated, replayed, and insufficiently evidenced requests. Actuator not invoked on any REFUSE case. T-09: no commitment → COMMITMENT_MISSING at actuator. T-10: amount mutation 500→5000 → COMMITMENT_MISMATCH_AT_ACTUATOR.  
*Limitation: In-memory mandate store. MockActuator. T-15 is the partial (enforce_still=False) — now closed by static audit.*

**12. Replay protection — concurrent 1/9**  
10 concurrent threads against the same release: 1 granted, 9 refused (CONSUMPTION_ALREADY_USED).  
*Limitation: Single Supabase store. Multi-instance TOCTOU not tested (F-31).*

**13. Owner continuity (CAT-01) enforced in both STILL paths**  
F-32 fixed. Owner change O1→O2/O3 refuses in both still_authority_adapter() and evaluate_release() internal STILL path. T-03 and T-18 confirmed.  
*Limitation: Internal tested only.*

---

## Section 2 — What Is NOT Proven

| Gap | Status |
|-----|--------|
| Delegation escalation refusal on live Railway | Fix deployed. 23/23 internal tests pass. **External confirmation pending — Alkama rerun in progress** |
| Real Paystack test reference | Architecture boundary proven. Real sk_test_ key needed to produce actual consequence_id |
| Multi-instance distributed atomicity | F-31: single-instance Railway only. Cross-replica replay not tested |
| Webhook retry idempotency | F-34: not tested, not claimed |
| Production actuator with live money | C2 scope throughout. Test mode only |
| Full endpoint proof coverage | 1,286 routes inventoried. 6 LIVE_VERIFIED. 1,278 NOT_ASSESSED |
| Regulatory certification | REGISTRATION_OR_DOI ≠ CERTIFICATION. No EU AI Act, ISO, FedRAMP established |
| Universal prevention of unauthorized actions | Tested paths only. Not all deployments. Not all code paths |

---

## Section 3 — Safe Claim Language

> Under tested conditions, the execution boundary required current standing, action-specific conditions, and a valid consequence commitment before permitting the tested consequence, and rejected tested stale, mutated, replayed, or insufficiently evidenced requests. The actuator independently verified the commitment — it does not rely on upstream trust alone. Blocked paths never reached the Paystack API.

> An independent external engineer reproduced the published verification procedure and confirmed issuance integrity and signature. The verifier correctly returned UNDETERMINED where live conditions could not be independently re-established.

> STILL adversarial suite: revoked, expired, ceiling-exceeded, unauthorized vendor, forged caller-supplied STILL, and unknown mandates — all refused on live Railway with real Supabase.

---

## Section 4 — Forbidden Claim Language

The following must not appear in any public communication:

- VeriSigil guarantees or prevents all unauthorized AI actions
- This is production-proven with live money
- All deployment paths or all code paths are governed
- Independently verified that all actions are admissible
- EU AI Act / ISO / FedRAMP certified or compliant
- STILL cannot be forged or bypassed
- Delegation is fully verified *(Alkama live rerun still pending)*
- Line count or architecture complexity implies proof
- We are the only system that does this

---

## Section 5 — The One Remaining Gate

**P1-A: Alkama delegation rerun on current live build**

Required:
1. Narrow child with valid parent scope and ceiling → ISSUE
2. Escalation probe (scope or ceiling exceeded) → DELEGATION_SCOPE_VIOLATION, state_mutation=NONE

When this closes:
- Delegation moves from INTERNAL to LIVE_VERIFIED
- PRODUCTION_CLAIM_ALLOWED is evaluated against written acceptance criteria
- Even then: Section 2 gaps remain as explicit limitations

**After Alkama confirms, PRODUCTION_CLAIM_ALLOWED is evaluated — not automatically flipped.**

---

## Section 6 — How to Challenge This Report

We invite independent adversarial testing.

**What we will accept:**
- Any test that reaches a defined control and produces a result different from what we claim
- Any alternate path that bypasses a stated boundary
- Any forged input that is accepted when it should be refused

**What we commit to:**
- Publish the result exactly as reported
- Fix any confirmed defect
- Credit the finder publicly
- Not reframe a failure as a test limitation

**Contact:** Publish your test procedure and raw result. We will respond within one working day.

**Public key for receipt verification:**  
`lJWG0Wabt6uATPu5Upo6UEHWGXQqMyi6LMKQC0xwpY8=`

**Zenodo DOI (doctrine):**  
`doi.org/10.5281/zenodo.20627386`

**Live endpoint:**  
`https://verisigil-api-production.up.railway.app`

---

*VeriSigil AI — scoped evidence for a consequence boundary, not a slogan.*  
*PRODUCTION_CLAIM_ALLOWED: False | LOCKED_CLAIM: NOT_YET_DELIVERED*
