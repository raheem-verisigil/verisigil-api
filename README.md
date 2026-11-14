# VeriSigil AI — Verifiable Consequence Boundaries

**Runtime control and evidence for consequential AI actions at declared execution boundaries.**

VeriSigil addresses a specific systems problem: when an AI-generated action is about to become consequential, can the system establish that the action is still authorized under the current conditions, bind the decision to the exact parameters, refuse when required evidence is missing or contradictory, and produce independently verifiable evidence?

VeriSigil is being developed to answer that question at declared, protected execution boundaries.

## Product architecture

- **Verifiable Consequence Boundaries** — the architectural boundary at which a consequential action is evaluated and controlled.
- **Runtime Authority** — authority and required conditions are evaluated for the action about to become real.
- **Parameter-Locked Execution** — the decision is bound to the exact action and parameters.
- **Fail-Closed Runtime** — inability to establish a required condition does not become implicit permission.
- **Cryptographic Execution Receipts** — signed evidence supports independent verification of the recorded decision.

VeriSigil complements existing identity, IAM, policy, model-safety, human-governance, and actuator systems. It does not replace them.

## Current phase: PROVE

The current evaluation is deliberately bounded. The current staging candidate includes a durable validation-receipt adapter and fail-closed execution-authorization middleware. Its tests exercise synthetic authority and capacity scenarios, receipt verification, and replay refusal.

Important limitations remain:
- The Terry scenario tests currently use a synthetic in-memory receipt-store adapter.
- The Supabase receipt schema and atomic consume function have been inspected and a direct SQL smoke test was reported successful, but the deployed API's insert/read/consume path is not yet independently verified end to end.
- Authority and state registries remain in-memory in the current staging harness.
- Process-restart recovery and cross-instance replay behavior are not yet proven.
- Downstream actuator enforcement and real payment execution are not proven.
- The current execution path uses Ed25519. Do not infer post-quantum signing.
- No current claim of Z3 proof execution, universal AI coverage, production-wide prevention, or regulatory certification is made.

## Current evaluation build

The current bounded evaluation candidate is on the [Terry staging branch](https://github.com/raheem-verisigil/verisigil-api/tree/security/terry-fail-closed-execution-20261113), at commit [dfa626d](https://github.com/raheem-verisigil/verisigil-api/commit/dfa626d309cf397f4e861a3449f258dcb6b5fdf5).

The isolated Railway staging service is:

https://verisigil-security-repair-test-staging.up.railway.app

**This is a staging evaluation surface, not the production API. Do not use production credentials or production data for reproduction.**

## Start here

1. Read [EVIDENCE_BASELINE.md](EVIDENCE_BASELINE.md) for the controlling claim and evidence status.
2. Read [TERRY_VALIDATION.md](TERRY_VALIDATION.md) for the synthetic adversarial scenario and its limits.
3. Follow [QUICKSTART.md](QUICKSTART.md) to reproduce the local test suite with synthetic environment values.
4. Use [CHALLENGE.md](CHALLENGE.md) to report a bounded, reproducible finding.

## Evidence discipline

Implemented behavior is not automatically tested behavior. A passing test is not automatically independent verification. A staging demonstration is not production-wide coverage. A cryptographic receipt proves the integrity and signature of the recorded artifact; it does not independently establish the truth of an external data source or prove that a downstream actuator enforced the authorization.

The authoritative status and remaining proof gates are maintained in [EVIDENCE_BASELINE.md](EVIDENCE_BASELINE.md).

**BUILD → PROVE → GENERALIZE → INTEROPERATE → STANDARDIZE**
