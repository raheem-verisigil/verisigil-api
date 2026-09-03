# VeriSigil AI — Claims Registry
**Date:** 2026-09-03 | **Phase:** PROOF CLOSURE

## Claim States

| Claim | Status | Evidence | Public Language |
|-------|--------|----------|-----------------|
| PRODUCTION_CLAIM_ALLOWED | **False** | Not yet evaluated | — |
| LOCKED_CLAIM | **NOT_YET_DELIVERED** | Gates not complete | — |
| Receipt integrity + Ed25519 | **VERIFIED** | Harold cold run V5 | ✅ Safe to post |
| UNDETERMINED correct behavior | **VERIFIED** | Harold cold run V5 | ✅ Safe to post |
| STILL adversarial 11/11 live | **DEMONSTRATED V4** | Live Railway + Supabase | ✅ Safe to post |
| Supabase persist + retrieve | **DEMONSTRATED V4** | Live Railway + Supabase | ✅ Safe to post |
| Tamper detection live | **DEMONSTRATED V4** | Live Railway | ✅ Safe to post |
| Actuator boundary (Paystack) | **DEMONSTRATED V4** | Architecture + placeholder key | ✅ Safe (with limitation noted) |
| COULD binding INV-P3 | **DEMONSTRATED V4** | Live Railway | ✅ Safe (with limitation noted) |
| Post-restart durability | **VERIFIED** | Alkama independent V4 | ✅ Safe to post |
| enforce_still=False 0 paths | **DEMONSTRATED V4** | Static audit P1-B | ✅ Safe to post |
| NOT_DIAGNOSTIC discipline | **DEMONSTRATED V5** | Public record | ✅ Safe to post |
| Replay protection 1/9 | **DEMONSTRATED V3** | Internal adversarial | ⚠️ V3 only — label as internal |
| Owner continuity CAT-01 | **DEMONSTRATED V3** | Internal adversarial | ⚠️ V3 only — label as internal |
| Execution admissibility 17/18 | **DEMONSTRATED V3** | Internal adversarial | ⚠️ V3 only — label as internal |
| Delegation scope enforcement | **INTERNAL ONLY** | 23/23 internal; Alkama live rerun pending | ❌ NOT in safe public claims until Alkama |
| Real Paystack reference | **NOT PROVEN** | Placeholder key only | ❌ Not claimable |
| Multi-instance atomicity | **NOT PROVEN** | F-31 single-instance | ❌ Not claimable |
| Distributed replay | **NOT PROVEN** | Not tested | ❌ Not claimable |
| Live money | **NOT PROVEN** | C2 scope only | ❌ Not claimable |
| Full endpoint coverage | **NOT PROVEN** | 6/1286 LIVE_VERIFIED | ❌ Not claimable |
| Regulatory certification | **NOT CLAIMABLE** | CLM-SCOPE-04 confirmed | ❌ Never |

## After Alkama Confirms (Checklist — all required)

- [ ] Alkama escalation refuse on live Railway build
- [ ] Composed STILL on real mandate through evaluate_release
- [ ] Paystack: clearly labeled placeholder vs real test reference
- [ ] Section 2 limitations still published
- [ ] No safe-claim language contradicts any NOT_PROVEN item

When all five are checked: PRODUCTION_CLAIM_ALLOWED moves to EVALUATION IN PROGRESS.
LOCKED_CLAIM remains NOT_YET_DELIVERED until composed path + actuator are demonstrated.

## Architecture Freeze

**IN EFFECT.** No new features. No new terminology. No new architecture.
Engineering objective: convert every remaining material claim boundary into independently reproducible evidence.

**Priority order:**
1. P1: Alkama live delegation rerun
2. P2: Composed STILL → COULD → commitment → actuator path
3. P3: Real Paystack test reference (Route A) or honest interface-only label (Route B)
4. P4: Distributed concurrency (before serious financial claims)
5. P5: Evidence package freeze + Proof Report v1 publish

