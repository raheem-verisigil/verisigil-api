# VeriSigil — Bounded Adversarial Challenge Protocol

**Status:** Open for bounded technical examination  
**Current phase:** PROVE  
**Controlling status:** [EVIDENCE_BASELINE.md](EVIDENCE_BASELINE.md)

## Purpose

We invite independent reviewers to challenge a narrow, reproducible proposition about VeriSigil's declared execution boundary:

> For the tested workflow, VeriSigil refuses to issue a fresh execution authorization when required authority, state, receipt integrity, proposal binding, or one-time-use conditions are absent, stale, contradicted, or already consumed.

This is not a claim that every AI action, endpoint, customer system, or external consequence is protected.

## Examination boundary

The current Terry scenario is a synthetic staging exercise. It covers:
- a proposal bound to an initial state assertion;
- successful pre-execution revalidation under the initial synthetic conditions;
- authority revocation after proposal creation;
- refusal to reuse the earlier revalidation;
- contradictory capacity evidence;
- restoration of consistent synthetic conditions and fresh authority;
- signed receipt verification; and
- one-time receipt replay refusal.

The scenario does **not** establish source authenticity for the synthetic capacity fixture, persistent authority/state registries, multi-replica operation, or downstream actuator enforcement.

## Safe reproduction

1. Review [EVIDENCE_BASELINE.md](EVIDENCE_BASELINE.md) and agree which proposition is being examined.
2. Use the isolated staging evaluation branch and synthetic test environment described in [QUICKSTART.md](QUICKSTART.md).
3. Run the focused tests and record the exact commit SHA, command, environment, and unedited output.
4. Attempt a controlled falsification: missing receipt, proposal substitution, receipt replay, stale authority, contradictory state, or a parameter change.
5. Verify the returned signed receipt independently using the repository verifier.
6. Classify the result using the categories below.

Do not point the test suite at production. Do not submit secrets, customer data, or private keys in a public issue.

## Result classification

- **PASS** — the defined control behaved as expected under the recorded conditions.
- **FAIL** — the defined control did not behave as expected; include the raw request/response and reproduction steps.
- **NOT_DIAGNOSTIC** — the test did not reach the intended control or the harness could not establish the required conditions.
- **NEW_FINDING** — an observed behavior reveals a material gap not already listed in the current evidence baseline.

A test result applies only to the exact path, build, configuration, and conditions exercised.

## Current exclusions

The following are not established by the current bounded scenario:
- real Paystack transaction execution or live movement of funds;
- enforcement by a real downstream customer actuator;
- complete endpoint or production-wide coverage;
- authority/state registry recovery after process restart;
- atomic replay prevention across two independent API instances;
- regulatory certification or legal compliance;
- universal AI safety or universal prevention of unauthorized consequences;
- Z3 proof execution in the current runtime; or
- post-quantum Dilithium / ML-DSA signing in the current execution path.

Reviewers are welcome to propose separate tests for these areas, but their status must remain **NOT PROVEN** until the corresponding evidence exists.

## Reporting a finding

Provide:
- exact repository commit and deployment identifier;
- test environment and configuration (excluding secrets);
- control and attack vector;
- expected behavior;
- raw observed result;
- whether the test reached the intended enforcement point; and
- the smallest reproducible case.

Confirmed failures will be recorded as failures, not relabeled after the fact. Confirmed limitations will remain visible in the evidence baseline.

**Evidence before expansion. Reproduction before trust.**
