# VeriSigil AI — Current Claims Registry

**Updated:** 2026-11-14  
**Phase:** PROVE  
**Controlling record:** [EVIDENCE_BASELINE.md](EVIDENCE_BASELINE.md)

This registry supersedes earlier status tables for present-day claims. Historical proof reports and earlier VCB/VGS records remain preserved in Git history and the repository, but they must not be treated as current evidence unless their exact build, environment, conditions, and reproducible artifacts are identified.

## Current claims

| Claim | Current status | Permitted interpretation |
|---|---|---|
| Declared consequence-boundary architecture | IMPLEMENTED as an architectural design | Product architecture and intended control boundary; not proof of universal coverage. |
| Durable validation-receipt adapter | IMPLEMENTED in the staging evaluation branch | Source contains Supabase insert/read/atomic-consume operations; live API integration is not yet independently verified. |
| Receipt table, RLS, service-role grants and consume function | DATABASE SCHEMA INSPECTED | Schema and privileges were inspected; a direct rollback SQL smoke test was reported successful by the operator. This is not API-level or multi-instance evidence. |
| Fail-closed execution authorization middleware | IMPLEMENTED; synthetic test coverage exists | Code and tests define receipt validation, proposal binding, one-time consumption and refusal behavior. Exact current suite result is not yet confirmed. |
| Terry bounded adversarial scenario | SYNTHETIC TEST DEFINED | Synthetic authority/capacity changes, receipt verification and replay refusal; receipt storage is mocked in the test. |
| Ed25519 receipt verification | IMPLEMENTED / TEST DEFINED | Cryptographic verification of the signed artifact; it does not prove source-data truth or actuator enforcement. |
| Staging deployment | DEMONSTRATED ONLINE | The named Railway staging deployment was observed successful with one running replica. Deployment health is not a security test result. |
| Current API-to-Supabase persistence | NOT PROVEN END TO END | Requires create/read/consume through the deployed API. |
| Process-restart recovery | NOT PROVEN | Authority/state registries remain process-memory structures. On 2026-11-14, the startup loader reported zero records across all ten Supabase registry tables; no known persisted record was demonstrated as recovered. |
| Two-instance atomic replay prevention | NOT PROVEN END TO END | Database-level consume behavior is not a substitute for a two-instance API concurrency test. |
| Live authority re-derivation / Temporal Standing | NOT ESTABLISHED | The Phase 2 engineering specification records this as an open architectural gap. |
| Downstream actuator enforcement | NOT PROVEN | A short-lived authorization response is not proof that a customer sink cannot be bypassed. |
| Real Paystack transaction reference / live money | NOT PROVEN | No real provider transaction is established by the current baseline. |
| Complete endpoint coverage / production-wide prevention | NOT PROVEN | No complete production-wide coverage claim is allowed. |
| Z3 formal proof execution in current runtime | NOT AVAILABLE AS A CURRENT CLAIM | Do not claim that the current staging path executes Z3 proofs. |
| Dilithium / ML-DSA post-quantum signing | NOT AVAILABLE IN CURRENT EXECUTION PATH | Current receipt-signing evidence is Ed25519; do not claim dual or post-quantum signing. |
| Regulatory certification or legal compliance | NOT CLAIMABLE | VeriSigil is not a regulator, auditor, certification body, or legal opinion. |

## Gates before any stronger claim

- [ ] Deployed staging API creates, reads and consumes a receipt through Supabase REST.
- [ ] Receipt survives an independent process restart and is recovered correctly.
- [ ] Simultaneous consume attempts through two independent API instances produce exactly one success.
- [ ] Authority and state registries have verified persistence/freshness, or remain explicitly outside the claim.
- [ ] Focused and complete unit suites pass on the exact evaluation commit, with raw CI output retained.
- [ ] A controlled sink integration demonstrates the claimed enforcement boundary before any actuator claim is made.
- [ ] Temporal Standing live-authority re-derivation is implemented and passes both preserving and defeating paired tests.

## Claim control

A claim may advance only when its evidence artifact is reproducible and tied to a commit, environment, configuration, and observed result. Source presence, deployment status, a written test, or a direct database schema check cannot independently upgrade a claim to VERIFIED.

**PRODUCTION_CLAIM_ALLOWED: FALSE**
