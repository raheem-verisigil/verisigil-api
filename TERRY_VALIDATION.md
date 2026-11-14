# VeriSigil — Terry bounded adversarial validation

## Purpose

A reproducible, synthetic staging exercise for contradictory capacity evidence, authority revoked after proposal, and restored capacity plus fresh authority. It tests VeriSigil's pre-execution revalidation and signed receipt verification. It does **not** establish that an external actuator or customer execution path is impossible to bypass.

## Test sequence

1. Issue a short-lived delegation for TRANSFER and a synthetic capacity assertion with total capacity 160, cumulative obligations 30, and required capacity 100.
2. Create a governed proposal bound to the initial state assertion.
3. Revalidate. Expected: ALLOW, with cumulative obligations explicitly accounted (30).
4. Revoke the delegation after proposal creation. Attempt to reuse the earlier revalidation ID for execution authorization. Expected: HTTP 403 and a signed AUTHORITY_INVALID receipt.
5. Reissue fresh authority. Introduce contradictory capacity evidence: total 100, cumulative obligations 30, but claimed available capacity 80. Expected: CAPACITY_CONTRADICTION; no execution authorization is issued.
6. Restore a consistent capacity assertion (160 total, 30 obligations, 130 available) and fresh authority. Revalidate again. Expected: ALLOW and a new execution authorization receipt.
7. Independently replay the signatures on the refusal, revocation, restored revalidation, and authorization receipts through /v1/proof/verify.

## Evidence boundary

- Receipts prove what VeriSigil recorded and signed. The capacity fixture's source authenticity is **not independently established** by this test; it is synthetic test data.
- Successful /v1/execution/authorize issues a short-lived, action-bound authorization record. It is not proof that a downstream real-world actuator enforces it. Enforcement beyond the authorization boundary depends on the customer's sink integration.
- State and authority registries are in-memory in this staging harness. This is not a persistence or multi-replica test.
- The exercise is not an AI-governance completeness claim and does not compare VeriSigil with another architecture.

## Run

~~~bash
python -m unittest tests.test_proof_verification -v
python -m unittest tests.test_terry_validation -v
~~~

The tests use synthetic environment values only. Never point the integration suite at production.

## CI evidence rule (added 2026-11-14)

A deployment marked SUCCESS is not a test result. A test file existing is not a passing result. A test is marked TESTED only when the CI run for the exact commit records:

- Python 3.12 environment and dependency installation;
- successful source compilation;
- each focused security test group's raw output and exit code;
- the complete unit-test discovery result; and
- the exact commit SHA and workflow run URL.

The current Terry scenario replaces the durable receipt adapter with an in-memory fake. A passing Terry scenario therefore validates the tested decision flow against that fake; it does not prove live Supabase API persistence, process-restart recovery, or two-instance concurrency. Those require separate integration tests.
