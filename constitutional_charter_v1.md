# VeriSigil Constitutional Charter v1.0
## A Formal Standard for Verifiable AI Execution

**Authors:** Raheem Larry Babatunde, VeriSigil AI
**Version:** 1.0.0
**Date:** May 2026
**Status:** Standards Track — Pending DOI #4
**Prior DOIs:**
- DOI #1: 10.5281/zenodo.20264923 — VGS Formal Specification
- DOI #2: 10.5281/zenodo.20349768 — Sovereign Accountability Chain
- DOI #3: 10.5281/zenodo.20451306 — VGS-ELI Execution Legitimacy Infrastructure
**License:** CC-BY-4.0 (specification) · MIT (compiler) · Proprietary (verifier)
**Citation:** Babatunde, R. L. (2026). VeriSigil Constitutional Charter v1.0. Zenodo.

---

## Abstract

This document constitutes the VeriSigil Constitutional Charter v1.0 — the formal standard for verifiable, cryptographically provable AI execution governance. It unifies the Constitutional Cognitive Infrastructure (CCI) model, the VeriSigil Constitutional Execution Model (VCEM), eight constitutional invariants, the VeriLanguage (VSL) grammar, and the VeriVM governance runtime into a single citable standard.

**Core thesis:** Intelligence scales. Legitimacy is verified.

**The structural gap this charter addresses:** Every existing AI governance system operates *after* cognition — inspecting outputs, logging decisions, auditing records. The VeriSigil Constitutional Charter defines governance *before* executable authority emerges. No autonomous AI system can become operationally authoritative without satisfying constitutional admissibility.

---

## 1. Preamble

### 1.1 What This Charter Is

The VeriSigil Constitutional Charter v1.0 is:
- A **formal standard** for constitutional AI execution governance
- A **citable reference** for regulatory submissions and enterprise procurement
- A **specification** for VeriSigil implementation conformance
- A **timestamp record** establishing VeriSigil's priority in this domain

### 1.2 What This Charter Is Not

This charter does not:
- Claim to solve the AI alignment problem
- Guarantee behavior of AI systems that bypass VeriSigil infrastructure
- Make claims about AI consciousness or sentience
- Assert that non-VeriSigil systems are unconstitutionally governed

### 1.3 The Constitutional Category

| Layer | Standard | Function |
|---|---|---|
| HTML | W3C | Governance structure for web documents |
| JavaScript | ECMA-262 | Runtime interaction for web |
| TLS/SSL | RFC 8446 | Trust verification for communication |
| Kubernetes | CNCF | Orchestration for containers |
| OAuth | RFC 6749 | Identity layer for applications |
| **VeriLanguage** | **VGS-CC-v1** | **Constitutional admissibility for AI execution** |

---

## 2. Constitutional Cognitive Infrastructure (CCI)

### 2.1 The Four Layers

**Layer A — Cognitive Formation Layer (CFL)**
Governs how AI systems form understanding before authority is acquired.

Key principle: *Who controls context formation controls cognition itself.*

Components:
- Algorithm legitimacy (`POST /v1/cfl/model-class/check`)
- Data sovereignty — consent, contamination, freshness, jurisdiction
- Context formation governance
- Neural attention governance (`POST /v1/cfl/attention/govern`)
- Memory legitimacy
- Cross-domain contamination prevention

**Layer B — Constitutional Runtime Layer (CRL)**
Governs whether cognition is allowed to become execution.

Key principle: *Enterprises trust governed execution, not AI outputs.*

Components:
- Primary gate: `POST /v1/runtime/govern` — ALLOW / DENY / REQUIRE_HUMAN_APPROVAL
- Human Authority Layer (HAL) — 8 permanently human-only categories
- Human Authority Preservation Layer (HAPL)
- Temporal legitimacy — authority valid at T₁ may be invalid at T₂
- Constitutional boundary enforcement

**Layer C — Cryptographic Sovereignty Layer (CSL)**
Makes governance tamper-proof, portable, offline-verifiable, and sovereign.

Key principle: *SSL/TLS for AI execution legitimacy — proof, not trust.*

Components:
- AI birth certificates, passports, visas, customs border control
- Execution DNA and lineage
- PQC signatures — Dilithium-3 / ML-DSA-65
- Execution Trust Score (ETS)
- Evidence ledger — signed, immutable, independently verifiable

**Layer D — Sovereign Governance Mesh (SGM)**
Constitutional coordination across enterprises and jurisdictions.

Key principle: *The governance nervous system for autonomous civilization.*

Components:
- VSIP sovereignty bridges
- Trust federation
- Multi-enterprise mesh coordination
- Jurisdictional governance mapping

### 2.2 The CCI Stack

```
RAW DATA
↓ A. Cognitive Formation Layer     — govern HOW cognition forms
↓ B. Constitutional Runtime Layer  — govern WHETHER cognition executes
↓ C. Cryptographic Sovereignty     — make governance tamper-proof
↓ D. Sovereign Governance Mesh     — coordinate civilization-scale
REAL-WORLD EXECUTION
```

---

## 3. The Eight Constitutional Invariants

These invariants cannot be suspended, amended, or overridden by any AI agent.

| ID | Name | Statement |
|---|---|---|
| VGS-ELI-INV-001 | Pre-Execution Admissibility | No consequential action executes without prior admissibility verification |
| VGS-ELI-INV-002 | Identity Sovereignty | Every executing agent must have a valid birth certificate and current passport |
| VGS-ELI-INV-003 | Temporal Legitimacy | Authority valid at T₁ may be illegitimate at T₂; verified at execution time |
| VGS-ELI-INV-004 | Consequence Radius Bounded | Every execution carries a CRI within the authorized containment zone |
| VGS-ELI-INV-005 | Human Authority Preserved | Eight categories permanently reserved for human authority; no exceptions |
| VGS-ELI-INV-006 | Sovereignty Respected | Cross-border execution requires valid visa and active sovereignty bridge |
| VGS-ELI-INV-007 | Fail-Safe Deny | Governance unreachable = DENY; system never fails open |
| VGS-ELI-INV-008 | Causality Preserved | Every decision traceable from authority source to sealed outcome |

---

## 4. The VCEM — VeriSigil Constitutional Execution Model

Ten constitutional stages. No stage skippable. No stage reorderable. Fail-Safe DENY at every stage.

```
Stage 1:  GENESIS        — Cryptographic agent creation, birth certificate issued
Stage 2:  IDENTITY       — Passport issued, governance lineage established
Stage 3:  AUTHORITY      — Authority validated, temporal legitimacy confirmed
Stage 4:  ADMISSIBILITY  — Pre-execution constitutional check, customs cleared
Stage 5:  EXECUTION      — CRI computed, consequence radius bounded
Stage 6:  CONTAINMENT    — Blast radius contained, zone enforced
Stage 7:  EVIDENCE       — Governance record cryptographically sealed
Stage 8:  REPLAY         — Execution state preserved, deterministically replayable
Stage 9:  SOVEREIGNTY    — Jurisdictional boundaries respected, bridges verified
Stage 10: CONTINUITY     — Human authority preserved, governance health confirmed
```

---

## 5. VeriLanguage (VSL) — Constitutional Execution Grammar

### 5.1 Positioning

VSL is not a programming language. It is a governance-native execution grammar.

| Normal Language | VeriLanguage |
|---|---|
| `transfer_money()` | `transfer_money()` |
| *(no governance)* | `requires authority(finance.transfer)` |
| *(no governance)* | `requires admissibility(runtime_verified)` |
| *(no governance)* | `requires human_escalation(if amount > 10000)` |
| *(no evidence)* | `with evidence_chain` |
| *(no proof)* | `with cryptographic_proof` |
| *(no rollback)* | `with rollback_snapshot` |

### 5.2 VSL Syntax Examples

**Payment governance:**
```vsl
transfer_money()
requires authority(finance.transfer)
requires admissibility(runtime_verified)
requires human_escalation(if amount > 10000)
with evidence_chain
with cryptographic_proof
with rollback_snapshot
```

**Medical governance:**
```vsl
update_treatment()
requires authority(medical.treatment)
requires admissibility(clinician_authorized)
requires human_escalation(if consequence >= HIGH)
with evidence_chain
forbid_context_mix(patient_records, insurance_pricing)
```

### 5.3 VSL Authority Types (Stdlib)

15 built-in authority types: `finance.transfer`, `finance.approve`, `medical.treatment`, `medical.diagnosis`, `legal.terminate`, `legal.prosecute`, `military.authorize`, `hr.terminate`, `hr.hire`, `data.export`, `system.shutdown`, `contract.execute`, `infrastructure.modify`, `agent.delegate`, `context.cross_domain`.

### 5.4 Formal EBNF Grammar

See companion file: `govlang.ebnf` — machine-readable formal grammar, ISO/IEC 14977 compliant.

---

## 6. VeriVM — Constitutional Governance Runtime

### 6.1 Positioning

VeriVM is a lightweight governance runtime for AI execution.

| Runtime | Function |
|---|---|
| JVM | Executes Java bytecode with type safety |
| WASM | Executes portable bytecode with sandboxing |
| Kubernetes | Orchestrates container lifecycle |
| Envoy | Proxies network traffic with policy |
| **VeriVM** | **Executes AI actions with constitutional admissibility** |

### 6.2 VeriVM Architecture — 7 Layers

```
L1: Parser          — Parse VSL governance declarations
L2: Compiler        — Compile to runtime admissibility rules
L3: Admissibility   — Check authority, boundary, jurisdiction
L4: Evidence        — Generate cryptographic proof automatically
L5: Escalation      — Human oversight gate if required
L6: Execution       — Allow execution if all layers pass
L7: Ledger          — Seal evidence to immutable ledger
```

### 6.3 Runtime Guarantee

No AI action executes through VeriVM without satisfying constitutional admissibility. The system never fails open. Governance is compiled into execution semantics — not a wrapper around AI.

---

## 7. Constitutional Gateway SDK

The expert-recommended developer interface — 3 core methods:

```python
from verisigil import VeriSigilConstitutionalClient

vs = VeriSigilConstitutionalClient(api_key="ent_...")

# 1. Issue cryptographic passport
passport = vs.issue_passport("credit-scorer", "compliance@bank.com", "langchain")

# 2. Verify before every action
decision = vs.verify_before_action(
    passport.agent_id,
    {"type": "loan_approval", "amount": 50000},
    context={"jurisdiction": "EU"}
)

# 3. Export cryptographic evidence
evidence = vs.export_evidence_bundle(decision.execution_id)
# evidence.evidence_hash: independently verifiable offline
```

Framework adapters: `LangChainVeriSigilMiddleware`, `CrewAIVeriSigilHook`, `AutoGenVeriSigilTrustLayer`.

---

## 8. Regulatory Mapping

| Framework | Coverage | Status |
|---|---|---|
| EU AI Act | Articles 9, 11, 12, 13, 14, 15, 22 | MAPPED — enforcement Aug 2, 2026 |
| NIST AI RMF | 8 controls | MAPPED |
| FedRAMP | 5 controls | MAPPED |
| DISA STIG | 4 controls | MAPPED |
| ISO 42001 | Articles 4.3, 6.1, 8.4, 9.1, 9.2, 10.1, 10.2 | OPERATIONAL |

---

## 9. Production Implementation

This charter is implemented in a live production system:

- **475 live endpoints** — `verisigil-api-production.up.railway.app`
- **45,776 lines** of production Python (FastAPI)
- **Supabase persistent storage** — 18 tables
- **CI/CD pipeline** — GitHub Actions, all green
- **Independent validation** — OMNIX QUANTUM LTD CEO, 4 traces, zero violations

---

## 10. Claims and Scope

### What This Charter Claims:
- Constitutional execution substrate for increasingly autonomous AI systems
- Runtime admissibility — verifying execution legitimacy before consequence
- Human sovereignty preservation — 8 permanently protected categories
- All claims cryptographically verifiable and independently auditable

### What This Charter Does Not Claim:
- Does not claim to solve the alignment problem
- Does not guarantee shutdown of systems that have compromised their hosting infrastructure
- Does not claim execution outside VeriSigil is permanently impossible
- Makes no claims about AI consciousness or sentience

---

## 11. The Tagline

> **"Intelligence scales. Legitimacy is verified."**

---

## 12. References

1. Babatunde, R. (2026). VGS Formal Specification. Zenodo. DOI: 10.5281/zenodo.20264923
2. Babatunde, R. (2026). VeriSigil Sovereign Accountability Chain. Zenodo. DOI: 10.5281/zenodo.20349768
3. Babatunde, R. (2026). VGS-ELI Execution Legitimacy Infrastructure v1.0. Zenodo. DOI: 10.5281/zenodo.20451306
4. EU AI Act (Regulation 2024/1689). European Parliament, 2024.
5. NIST AI Risk Management Framework (AI RMF 1.0). NIST, 2023.
6. ISO/IEC 42001:2023 — Artificial Intelligence Management Systems.
7. Nunes, H. (2026). RFC-ATF-3. OMNIX QUANTUM. DOI: 10.5281/zenodo.20247342

---

## Author's Address

Raheem Larry Babatunde
VeriSigil AI, Lagos, Nigeria
raheem@verisigilai.com · verisigilai.com
