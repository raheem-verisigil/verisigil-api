# ⬡ VeriSigil AI — Runtime Governance Infrastructure

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20264923.svg)](https://doi.org/10.5281/zenodo.20264923)
[![Conformance](https://img.shields.io/badge/conformance-80%2F80-green)](https://verisigil-api-production.up.railway.app/v1/conformance/verify)
[![Version](https://img.shields.io/badge/version-0.7.2-cyan)](https://verisigil-api-production.up.railway.app/health)
[![License](https://img.shields.io/badge/license-CC%20BY%204.0-blue)](https://creativecommons.org/licenses/by/4.0/)

## Formal Specification

**DOI:** https://doi.org/10.5281/zenodo.20264923

VeriSigil Governance Specification (VGS-001 to VGS-011) is formally published on Zenodo under CC BY 4.0. The specification is citable, versioned, and permanently archived.

---

## What Is VeriSigil

VeriSigil is **runtime governance infrastructure for autonomous AI agents** — the enforcement layer between agent intent and agent action.

> "Governance must happen before execution — not after. A log proves what happened. A runtime gate prevents the wrong thing from happening."

---

## Governance Specification (VGS)

| Spec | Description | Status |
|------|-------------|--------|
| VGS-001 | Runtime Admissibility | ✅ Live |
| VGS-002 | Governance State Machine | ✅ Live |
| VGS-003 | Human Approval Invariants | ✅ Live |
| VGS-004 | Cryptographic Governance Receipts | ✅ Live |
| VGS-005 | Intent-Bound Execution Protocol | ✅ Live |
| VGS-006 | Execution Authority Token (EAT) | ✅ Live |
| VGS-007 | Immutable Evidence Classification | ✅ Live |
| VGS-008 | Offline Forensic Verifier | ✅ Live |
| VGS-009 | Formal Mathematical Proofs (Z3 SMT) | ✅ Live |
| VGS-010 | Jurisdiction-Aware Admissibility | ✅ Live |
| VGS-011 | Governance Continuity Engine (GCS) | ✅ Live |

---

## Formal Verification

### Z3 SMT Proofs — All UNSAT

```
VFGS-INV-001  HIGH consequence gate        UNSAT — no counterexample exists
VFGS-INV-002  Financial exposure limit     UNSAT — ∀ amount ∈ ℝ⁺
VFGS-INV-003  Monotonic authority reduction UNSAT
VFGS-INV-004  Trust score floor            UNSAT — ∀ trust ∈ [0, 0.50)
```

### TLA+ Formal State Machine

`VeriSigilGovernance.tla` — 5 safety theorems + 2 liveness properties. TLC model checker ready.

### Conformance Vectors

```
POST /v1/conformance/verify
→ total_vectors: 80
→ passed: 80
→ verdict: ALL CONFORMANCE VECTORS PASS
```

Cross-runtime parity verified: Python + Node.js produce identical hashes.

---

## Named Invariant Taxonomy

| ID | Name | Enforcement Location |
|----|------|---------------------|
| VER-INV-001 | Evidence Classification Hash Binding | classify_evidence() |
| VER-INV-002 | Runtime Guard Latency Bound | /v1/guard/verify |
| VER-INV-003 | Audit Log Append-Only Immutability | chain_append() |
| VER-INV-004 | Classification Transition Prohibition | CLASSIFICATION_TRANSITION_MATRIX |
| VER-INV-005 | Jurisdiction Resolver Determinism | resolve_jurisdiction() |
| VER-INV-006 | Authority Collapse Propagation | propagate_revocation() |
| VER-INV-007 | Pre-Remediation Evidence Capture | propagate_revocation() → FRI |
| VER-INV-008 | Canonical Serialization Cross-Runtime Parity | canonical_serialize() |

---

## Cryptography

| Algorithm | Standard | Purpose |
|-----------|----------|---------|
| Ed25519 | RFC 8037 | Immediate security |
| Dilithium-3 | NIST FIPS 204 (ML-DSA-65) | Post-quantum security |

Dual signing on every governance receipt. ATF-compatible.

---

## Jurisdiction Coverage (VGS-010)

| Regime | Jurisdiction | Philosophy |
|--------|-------------|------------|
| EU_AI_ACT | European Union | Compliance-first |
| US_NIST | United States | Innovation-first |
| CN_AI_LAW | China | State-aligned |
| GCC_DIFC | UAE/GCC | Sovereign-innovation |

---

## Repository Contents

```
main.py                    VGS-001 through VGS-011 — full implementation
vfgs.py                    Z3 formal proofs
verisigil_sdk.py           Python SDK
verisigil_sdk.js           Node.js SDK
verisigil_verify.py        Offline forensic verifier (VGS-008)
VeriSigilGovernance.tla    TLA+ formal specification
conformance_vectors.json   80 deterministic conformance vectors
test_conformance.js        Node.js conformance test suite (86/86)
requirements.txt           Dependencies
```

---

## Live API

```
Base URL: https://verisigil-api-production.up.railway.app
Docs:     https://verisigil-api-production.up.railway.app/docs
Health:   https://verisigil-api-production.up.railway.app/health
```

All endpoints require: `x-api-key: your-api-key`

---

## Key Endpoints

```
POST /v1/guard/verify           Runtime Guard — ALLOW/DENY/REQUIRE_HUMAN_APPROVAL
POST /v1/eat/issue              Execution Authority Token
POST /v1/eat/validate           Validate EAT at action boundary
POST /v1/jurisdiction/resolve   Jurisdiction-aware admissibility
POST /v1/formal/prove           Z3 formal proofs
POST /v1/formal/certificate     Proof certificate (VSGCERT-*)
GET  /v1/invariants             40 governance invariants
GET  /v1/invariants/named       VER-INV-001 through VER-INV-008
POST /v1/conformance/verify     80 conformance vectors
POST /v1/evidence/verify        Reclassification attack detection
POST /v1/continuity/chain/revoke Authority collapse propagation
GET  /v1/crypto/status          Dilithium-3 + Ed25519 status
```

---

## Relationship to ATF

VeriSigil and the Agent Trust Fabric (ATF, RFC-ATF-1 through RFC-ATF-3 by Harold Alberto Nunes Rodelo, OMNIX QUANTUM) address the same missing infrastructure layer from complementary implementations.

| ATF | VeriSigil |
|-----|-----------|
| Intra-domain authority governance | Inter-domain jurisdiction enforcement |
| Formal RFC specifications | VGS-001 through VGS-011 |
| ML-DSA-65 signatures | Dilithium-3 + Ed25519 dual signing |
| Digital asset markets | Enterprise · Legal · Finance · GCC |

DOI: [RFC-ATF-1](https://doi.org/10.5281/zenodo.20155016)

---

## Formal Specification Citation

```
Babatunde, R. L. (2026). VeriSigil Governance Specification (VGS-001 to VGS-011).
Zenodo. https://doi.org/10.5281/zenodo.20264923
```

---

## Commercial Deployment

| Tier | Price | Target |
|------|-------|--------|
| Starter | $49/month | Developers |
| Professional | $499/month | Teams |
| Enterprise | $2,499/month | Organizations |

👉 **https://verisigilai.com**

---

*Built in Lagos, Nigeria 🇳🇬 · CC BY 4.0 · VGS v1.0*
