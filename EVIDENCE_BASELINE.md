# VeriSigil — Current Evidence Baseline

**Baseline date:** 2026-11-14  
**Product phase:** PROVE  
**Scope:** Current bounded staging implementation; not a production-readiness declaration.

This document is the controlling technical baseline for the current evaluation. Historical specifications, earlier proof reports, prior demonstrations, and roadmap material remain part of the project's record, but they do not override the status below unless a claim is tied to a current, reproducible artifact and its exact execution conditions.

## 1. Product definition

VeriSigil is runtime control and evidence infrastructure for consequential AI actions at **declared execution boundaries**.

For a registered protected workflow, the intended control sequence is:

1. Identify the actor and the authority relevant to the action.
2. Establish the current conditions required by the workflow.
3. Bind the decision to the exact action and parameters.
4. Refuse when required conditions cannot be established or are contradicted.
5. Issue a short-lived authorization at the declared boundary.
6. Produce cryptographically verifiable evidence of the decision.

The architectural objective remains **Verifiable Consequence Boundaries**. The current engineering phase is proof closure on a bounded reference path, not expansion into a universal AI governance layer.

VeriSigil does not replace IAM, policy engines, model safety, human governance, or the customer's downstream actuator. It does not claim universal coverage, universal prevention of unauthorized consequences, or regulatory certification.

## 2. Current implementation under evaluation

- Repository: raheem-verisigil/verisigil-api
- Evaluation branch: security/terry-fail-closed-execution-20261113
- Staging commit: dfa626d309cf397f4e861a3449f258dcb6b5fdf5
- Staging service: verisigil-security-repair-test
- Staging URL: https://verisigil-security-repair-test-staging.up.railway.app
- Environment: Railway staging

The deployment was observed as SUCCESS, with one running replica and no active Railway warnings or recent failed deployments at the time of this baseline. Service health is operational evidence only; it is not evidence that the security properties below have passed.

The deployed branch is an evaluation branch. The production service is not the target of this test plan and must not be used for test execution.

## 3. Evidence status

| Capability | Current status | What the evidence establishes |
|---|---|---|
| Durable validation-receipt adapter | Implemented in the evaluation branch | Supabase REST insert/read and atomic-consume adapter code exists. Live API-level integration is not yet independently verified. |
| Receipt table and database controls | Schema inspected; SQL smoke test operator-reported as passed | Table exists, RLS is enabled, expected columns and service-role grants were inspected, and the consume function is SECURITY DEFINER. A rollback-based SQL test reported first consume succeeds and second consume returns no record. |
| Fail-closed execution authorization middleware | Implemented; synthetic test coverage exists | Middleware checks the stored receipt, proposal binding, signature and one-time consumption before issuing a short-lived authorization. The current Terry test substitutes an in-memory fake receipt store. |
| Missing/mismatched/replayed receipt refusal | Test cases present; exact current CI result not confirmed | The code and tests define these refusal cases. Do not report a passing suite until the exact commit's test output is available. |
| Terry bounded scenario | Synthetic test defined | Exercises authority revocation, contradictory capacity evidence, restored authority/conditions, signed receipt verification and replay refusal. Inputs are synthetic. |
| Authority and state registries | In-memory in the current staging harness | Durable restart recovery and cross-replica consistency are not established. |
| Downstream actuator enforcement | Not proven | An authorization response is not proof that a customer sink or external system cannot be bypassed. |
| Real payment execution/reference | Not proven | No real Paystack transaction reference is established by this baseline. |
| Multi-instance atomicity | Not proven end-to-end | The database consume function has a SQL-level atomicity smoke test; two independent API instances have not been exercised together. |
| Formal Z3 proof execution | Not available as a current runtime proof claim | Do not claim that current staging runs Z3 proofs. |
| Post-quantum Dilithium / ML-DSA signing | Not available in the current execution path | Current receipt signing evidence is Ed25519; do not claim dual or post-quantum signing. |
| Production readiness or regulatory certification | Not claimable | No production-wide control or certification conclusion follows from this staging baseline. |

### Important distinction about the Terry tests

tests/test_terry_validation.py replaces the durable receipt adapter functions with an in-memory fake store during the test. Those tests can exercise the middleware's decision flow and replay behavior against the fake, but they do not prove that the deployed API successfully writes, reads, and consumes records through Supabase.

The SQL smoke test exercises the database function directly. It does not prove the deployed API's REST integration, process-restart recovery, or concurrent consumption across independent API instances.

## 4. Remaining proof gates

These are engineering gates for strengthening the product, not reasons to change its architecture:

1. **API-to-database integration:** create a receipt through the deployed staging API, read it back through a separate request/process, consume it, and verify replay refusal through the API.
2. **Restart recovery:** create durable receipt state, restart the staging process, then prove that the receipt can still be read and correctly consumed.
3. **Independent-instance concurrency:** send simultaneous consume attempts through two separate API instances and prove exactly one succeeds.
4. **Registry durability and freshness:** either implement and test authoritative persistence/re-derivation for the authority and state registries, or keep those claims explicitly outside the current proof boundary.
5. **CI evidence:** run the focused security tests and complete unit suite against the exact evaluation commit; retain the unedited logs and commit SHA.
6. **Sink enforcement:** integrate a controlled test actuator with an independently observable side effect before claiming enforcement beyond the authorization boundary.
7. **Live-authority re-derivation:** close the documented Temporal Standing gap and test both a standing-preserving and standing-defeating authority change.

No gate should be marked complete from source inspection alone. Each requires an executable test, an observed result, and a traceable commit/environment.

## 5. Bounded test proposition

The current external examination should test one narrow proposition:

> For a declared workflow, VeriSigil will not issue a fresh execution authorization when the required authority, state, receipt integrity, proposal binding, or one-time-use condition is absent, stale, contradicted, or already consumed.

The test must identify the exact workflow and protected boundary; initial authority and state fixtures; exact action and parameters; mutation or adversarial condition; expected refusal/allow result; observable state change (or absence of one); receipt and independent verification method; and limitations of the test harness.

A passing test proves only the proposition and execution conditions it actually exercises.

## 6. Evidence classification

- **IMPLEMENTED** — code exists; behavior has not necessarily been executed.
- **TESTED** — an executable test ran and its output is retained.
- **DEMONSTRATED** — behavior was observed in the named environment and conditions.
- **INDEPENDENTLY VERIFIED** — another party reproduced the defined result using the published procedure and evidence.
- **NOT PROVEN** — no sufficient evidence exists for the claim.
- **OUT OF SCOPE** — the current examination does not test the capability.

Never upgrade a status merely because a deployment is online, a test is written, or a database object exists.

## 7. Architecture and change control

The existing architecture and terminology remain frozen during this proof-closure phase. No new product category or feature layer is being introduced to answer this review.

The engineering sequence remains:

**BUILD → PROVE → GENERALIZE → INTEROPERATE → STANDARDIZE**

The immediate objective is to close the evidence gaps in the current declared execution boundary while preserving the broader product direction.

## 8. Reproduction entry points

- [Terry bounded validation](TERRY_VALIDATION.md)
- [Challenge protocol](CHALLENGE.md)
- [Quickstart](QUICKSTART.md)
- [Phase 2 engineering gap](PHASE2_ENGINEERING_SPEC.md)
- [Current evaluation branch](https://github.com/raheem-verisigil/verisigil-api/tree/security/terry-fail-closed-execution-20261113)
- [Exact staging commit](https://github.com/raheem-verisigil/verisigil-api/commit/dfa626d309cf397f4e861a3449f258dcb6b5fdf5)

**This baseline is a status record, not a certification, audit opinion, or guarantee of safety.**
