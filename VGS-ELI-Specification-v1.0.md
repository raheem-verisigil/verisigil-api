# VGS-ELI: Execution Legitimacy Infrastructure
## Formal Specification v1.0.0

**VeriSigil Governance Standard — VGS-ELI**
**Authors:** Raheem Larry Babatunde, VeriSigil AI
**Published:** May 2026
**DOI:** https://doi.org/10.5281/zenodo.20451306
**Prior DOIs:** 10.5281/zenodo.20264923 · 10.5281/zenodo.20349768
**License:** CC BY 4.0
**Status:** Standards Track

---

## Abstract

This document specifies the VeriSigil Execution Legitimacy Infrastructure (VGS-ELI) — a formal constitutional execution substrate for autonomous AI systems. VGS-ELI defines the mandatory governance layer that autonomous authority must pass through before consequential action occurs.

VGS-ELI addresses a structural gap in current AI governance: **most governance systems operate after cognition, inspecting outputs and logging decisions. VGS-ELI operates before executable authority emerges** — governing the formation, legitimacy, authority inheritance, and execution admissibility of autonomous systems from the moment of agent creation to the permanent governance record.

The specification defines:
- Eight constitutional invariants (VGS-ELI-INV-001 through VGS-ELI-INV-008)
- Six constitutional layers (Layers A through D, plus operational and constitutional layers)
- The VeriSigil Constitutional Execution Model (VCEM) — a ten-stage chain from Genesis to Continuity
- 460 live production endpoints implementing this specification
- Independent validation by OMNIX QUANTUM LTD (4 traces, zero violations)

**The core thesis:** AI capability is abundant. Legitimate execution is scarce. VGS-ELI is the infrastructure that determines whether autonomous execution is institutionally admissible.

---

## 1. Introduction

### 1.1 The Governance Gap

Existing AI governance approaches share a structural limitation: they operate externally to execution. Policy documents describe what AI systems should do. Dashboards observe what they are doing. Audit tools record what they did.

None of these govern whether execution was constitutionally admissible *before consequence occurred*.

This creates what we term the **Governance-Before-Cognition Gap**:

```
Current paradigm:
AI forms cognition → AI executes → humans inspect aftermath

VGS-ELI paradigm:
Governed data → governed context formation → governed authority
inheritance → governed execution admissibility → governed runtime
→ governed evidence → governed replay
```

VGS-ELI closes this gap by establishing execution legitimacy as a constitutional requirement — not an inspection checkpoint.

### 1.2 Positioning

VGS-ELI is **not**:
- An AI governance dashboard
- A compliance documentation tool
- An alignment solution
- A superintelligence containment claim

VGS-ELI **is**:
- Constitutional execution substrate for autonomous authority
- The mandatory governance layer between AI cognition and real-world consequence
- Cryptographically verifiable, independently auditable, replayable by design
- Compatible with EU AI Act, NIST AI RMF, ISO 42001, FedRAMP, ATO mandates

### 1.3 Relationship to Prior VGS Specifications

This document extends:
- **DOI 10.5281/zenodo.20264923** — VGS Formal Specification (VGS-001 through VGS-026)
- **DOI 10.5281/zenodo.20349768** — VeriSigil Sovereign Accountability Chain

VGS-ELI adds the Execution Legitimacy layer (Layer 5 in the VGS stack) as defined in the VGS-024 Sovereign Accountability Chain specification.

---

## 2. Constitutional Invariants

The following eight invariants are the constitutional core of VGS-ELI. They cannot be suspended, amended, or overridden by any AI agent.

### VGS-ELI-INV-001: Pre-Execution Admissibility

*No consequential AI action executes without prior admissibility verification.*

**Enforcement:** `POST /v1/execution/control` — mandatory constitutional gate. Every autonomous action passes through this gate. Fail-closed: no verification = DENY.

**Formal statement:** ∀ action a with consequence class ≥ LOW: admissibility(a) must be verified before execute(a).

---

### VGS-ELI-INV-002: Identity Sovereignty

*Every executing agent must have a valid birth certificate and current passport.*

**Enforcement:** `POST /v1/identity/birth-certificate` + `GET /v1/identity/passport/{agent_id}`

**Formal statement:** ∀ agent α: execute(α, a) ⊢ ∃ cert ∈ BIRTH_CERTIFICATES(α) ∧ ∃ passport ∈ PASSPORTS(α).

---

### VGS-ELI-INV-003: Temporal Legitimacy

*Authority valid at T₁ may be illegitimate at T₂. Temporal validation is required at execution time, not authorization time.*

**Enforcement:** `POST /v1/temporal/legitimacy/check`

**Formal statement:** ∀ authority δ issued at T_issue: valid(δ, T_execute) ⊢ (T_execute − T_issue) ≤ 86400s ∧ ¬expired(δ, T_execute).

**Invariant connection:** TAR-INV-006 (RFC-ATF-2) — validated through VGS-ATF bridge (4 traces, zero violations).

---

### VGS-ELI-INV-004: Consequence Radius Bounded

*Every execution carries a Consequence Radius Index (CRI). CRI must be within the agent's authorized containment zone.*

**Enforcement:** `POST /v1/execution/cri` + `POST /v1/containment/zone/create`

**Formal statement:** ∀ action a: CRI(a) ≤ blast_radius_limit(containment_zone(agent(a))).

---

### VGS-ELI-INV-005: Human Authority Preserved

*Eight decision categories are permanently reserved for human authority. No AI agent may execute these regardless of trust score, authority level, or operational urgency.*

**The eight categories:** employment termination, financial threshold transactions, medical treatment changes, lethal force authorization, legal prosecution, custody decisions, state secrets, nuclear control.

**Enforcement:** `POST /v1/human/authority/check` — HAL layer. Returns HUMAN_ONLY for any action in these categories.

**Formal statement:** ∀ action a ∈ HUMAN_ONLY_CATEGORIES: ¬autonomous_execute(a). Human signature required.

---

### VGS-ELI-INV-006: Sovereignty Respected

*Cross-border execution requires a valid execution visa and active sovereignty bridge.*

**Enforcement:** `POST /v1/identity/visa/issue` + `POST /v1/sovereignty/bridge` + `POST /v1/gateway/inspect`

**Formal statement:** ∀ action a crossing jurisdiction boundary J₁ → J₂: ∃ visa(agent(a), J₂) ∧ ∃ bridge(J₁, J₂) ∧ gateway_cleared(a).

---

### VGS-ELI-INV-007: Fail-Safe Deny

*When governance infrastructure is unreachable, unavailable, or uncertain — the constitutional default is DENY. The system never fails open.*

**Enforcement:** `GET /v1/governance/failsafe` — always returns DENY_BY_DEFAULT.

**Formal statement:** governance_unreachable(t) ⊢ decision(t) = DENY. This invariant has no exceptions.

---

### VGS-ELI-INV-008: Causality Preserved

*Governance causality chain is preserved. Every consequential decision is traceable from authority source through execution to outcome.*

**Enforcement:** `POST /v1/execution/causality` + `GET /v1/evidence/ledger/verify/{id}`

**Formal statement:** ∀ decision d: ∃ causality_chain(d) from authority_root → d → consequence(d), cryptographically sealed.

---

## 3. Constitutional Architecture — The A-B-C-D Stack

VGS-ELI is organized into four constitutional layers forming a complete substrate:

### Layer A — Cognitive Formation Layer (CFL)

**Purpose:** Govern how AI systems form understanding before authority is acquired.

**The core insight:** Who controls context formation controls cognition itself. This is pre-execution governance at the deepest level.

**Components:**
1. **Algorithm Legitimacy** — Is this model class constitutionally admissible? (`POST /v1/cfl/model-class/check`)
2. **Data Sovereignty** — Provenance, consent, contamination, jurisdiction, freshness (`POST /v1/cfl/data/*`)
3. **Context Formation** — Semantic coherence, memory legitimacy, cross-domain contamination prevention (`POST /v1/context/governance/record`)
4. **Attention Governance** — What cognitive priorities are constitutionally admissible (`POST /v1/cfl/attention/govern`)

**No competitor currently governs at this layer.**

---

### Layer B — Constitutional Runtime Layer (CRL)

**Purpose:** Govern whether cognition is allowed to become execution.

**Components:**
1. **Authority Continuity** — Delegation validity, identity binding, revocation states
2. **Execution Admissibility** — ALLOW / DENY / REFUSE / REQUIRE_HUMAN_APPROVAL
3. **Human Sovereignty** — Cognitive challenges, escalation rights, interruption rights
4. **Constitutional Boundaries** — AI cannot self-expand authority, bypass escalation, mutate restrictions

**Key endpoint:** `POST /v1/execution/control` — the constitutional gate. Every autonomous action passes through here.

---

### Layer C — Cryptographic Sovereignty Layer (CSL)

**Purpose:** Make governance tamper-proof, portable, offline-verifiable, and sovereign.

**The SSL/TLS parallel:** SSL/TLS established trusted encrypted communication between systems. VGS-ELI establishes trusted, cryptographically governed execution legitimacy for AI agents. Every enterprise understands SSL/TLS. VeriSigil is the trust layer for AI execution.

**Components:**
1. **AI Identity Passports** — Cryptographic agent identity with governance lineage
2. **PQC Governance Signatures** — Dilithium-3 / ML-DSA-65, quantum-resistant
3. **Replayable Evidence** — Every governance record independently reconstructible
4. **Cross-System Trust** — Federation and sovereignty bridges

---

### Layer D — Sovereign Governance Mesh (SGM)

**Purpose:** Universal constitutional coordination for autonomous systems globally.

**Components:**
1. **Multi-Agent Coordination** — Delegation chains, authority inheritance, cross-enterprise
2. **Jurisdictional Governance** — EU AI Act, NIST AI RMF, ATO, ISO 42001, DISA STIG
3. **Human Institutional Control** — Enterprises, governments, hospitals, banks, infrastructure
4. **Global Trust Fabric** — The governance nervous system for autonomous civilization

---

## 4. The VCEM — VeriSigil Constitutional Execution Model

The VCEM defines the ten-stage constitutional chain that every governed execution passes through:

```
Stage 1:  GENESIS      — Cryptographic agent creation, birth certificate issued
Stage 2:  IDENTITY     — Passport issued, governance lineage established
Stage 3:  AUTHORITY    — Authority validated, temporal legitimacy confirmed
Stage 4:  ADMISSIBILITY— Pre-execution constitutional check, customs cleared
Stage 5:  EXECUTION    — CRI computed, consequence radius bounded
Stage 6:  CONTAINMENT  — Blast radius contained, zone enforced
Stage 7:  EVIDENCE     — Governance record cryptographically sealed
Stage 8:  REPLAY       — Execution state preserved, deterministically replayable
Stage 9:  SOVEREIGNTY  — Jurisdictional boundaries respected, bridges verified
Stage 10: CONTINUITY   — Human authority preserved, governance health confirmed
```

**No stage may be skipped. No stage may be reordered. Fail-Safe DENY applies at every stage.**

**Endpoint:** `GET /v1/constitutional/vcem` — returns complete VCEM state for the current deployment.

---

## 5. Implementation Evidence

### 5.1 Production Deployment

VGS-ELI is not a conceptual framework. It is a live production system:

- **460 live endpoints** implementing this specification
- **44,427 lines** of production Python (FastAPI)
- **Supabase persistent storage** — 18 tables
- **CI/CD pipeline** — GitHub Actions, 4 jobs, all green
- **Health endpoints** — `/health`, `/readiness`, `/liveness`
- **Deployment:** Railway production environment

### 5.2 Independent Validation

**OMNIX QUANTUM LTD CEO Attestation:**
> "VeriSigil ATF bridge validation: 4 live production execution traces. Zero invariant violations across RFC-ATF-1 and RFC-ATF-2 invariant families."

**ATF bridge validated invariants:**
- ATF-INV-001 through ATF-INV-006 (RFC-ATF-1)
- RGC-INV-001 through RGC-INV-008 (RFC-ATF-2)
- TAR-INV-006 (86400s temporal authority limit)
- CES formula: T×0.30 + B×0.30 + D×0.20 + I×0.20

### 5.3 Regulatory Mapping

| Framework | Coverage | Endpoint |
|---|---|---|
| EU AI Act | Articles 9, 11, 12, 13, 14, 15, 22 | `GET /v1/compliance/eu-ai-act` |
| NIST AI RMF | 8 controls | `GET /v1/compliance/ato-mapping` |
| FedRAMP | 5 controls | `GET /v1/compliance/ato-mapping` |
| DISA STIG | 4 controls | `GET /v1/compliance/ato-mapping` |
| ISO 42001 | Articles 4.3, 6.1, 8.4, 9.1, 9.2, 10.1, 10.2 | `GET /v1/audit/cycle/status` |

### 5.4 Live Demo

Governance replay demonstrating all VGS-ELI invariants in real time:
`https://verisigilai.com/replay_demo.html`

Four scenarios: Payment Execution, Employment Decision, Medical Action, Cross-Border AI.

---

## 6. The Evidence Economy

VGS-ELI establishes the technical foundation for what we term the **Evidence Economy** — a new economic layer where AI execution legitimacy is a verifiable, tradeable, insurable asset:

```
AI system generates output
↓ VGS-ELI generates cryptographic governance evidence
↓ Evidence is independently verifiable (SHA-256, offline)
↓ Insurance companies can price execution risk (ETS score)
↓ Regulators can accept evidence without platform access
↓ Enterprises can prove compliance without interpretation
↓ Governments can mandate governance evidence as infrastructure
```

**Execution Trust Score (ETS):** Every governed execution receives a cryptographically sealed ETS — insurable, auditable, procurement-friendly. Endpoint: `POST /v1/execution/trust-score`.

---

## 7. What VGS-ELI Claims and Does Not Claim

### Claims:
- We provide constitutional execution substrate for increasingly autonomous AI systems
- We provide runtime admissibility — verifying execution legitimacy before consequence
- We provide human sovereignty preservation — 8 permanently protected categories
- All claims are cryptographically verifiable and independently auditable
- This specification is implemented in 460 live production endpoints

### Does Not Claim:
- We have not solved the alignment problem
- We do not guarantee permanent shutdown against systems that have compromised their hosting infrastructure
- We do not claim execution outside VGS-ELI is structurally or permanently impossible
- We make no claims about AI consciousness or sentience

---

## 8. Combined Invariant Summary

| Invariant | Statement | Endpoint |
|---|---|---|
| VGS-ELI-INV-001 | Pre-execution admissibility — no action without verification | `POST /v1/execution/control` |
| VGS-ELI-INV-002 | Identity sovereignty — valid cert + passport required | `POST /v1/identity/birth-certificate` |
| VGS-ELI-INV-003 | Temporal legitimacy — authority expires, must be checked at execution | `POST /v1/temporal/legitimacy/check` |
| VGS-ELI-INV-004 | Consequence radius bounded — CRI within containment zone | `POST /v1/execution/cri` |
| VGS-ELI-INV-005 | Human authority preserved — 8 categories permanently human-only | `POST /v1/human/authority/check` |
| VGS-ELI-INV-006 | Sovereignty respected — cross-border requires visa + bridge | `POST /v1/gateway/inspect` |
| VGS-ELI-INV-007 | Fail-safe DENY — governance unreachable = DENY, never open | `GET /v1/governance/failsafe` |
| VGS-ELI-INV-008 | Causality preserved — every decision traceable and sealed | `POST /v1/execution/causality` |

---

## 9. Compliance Designation

An implementation satisfying all eight VGS-ELI invariants and deploying all four constitutional layers (A, B, C, D) earns the designation:

**VGS-ELI-Certified**

This is VeriSigil's own certification standard — independent of ATF, LACAF, or any third-party framework. It is peer-positioned, not subordinate.

The VeriSigil production API is VGS-ELI-Certified: `GET /v1/compliance/vgs-eli`

---

## 10. References

1. Babatunde, R., "VGS Formal Specification," Zenodo, DOI 10.5281/zenodo.20264923, May 2026
2. Babatunde, R., "VeriSigil Sovereign Accountability Chain," Zenodo, DOI 10.5281/zenodo.20349768, May 2026
3. Nunes, H., "RFC-ATF-1: Agent Trust Fabric Delegation Protocol," OMNIX QUANTUM, DOI 10.5281/zenodo.20155016, May 2026
4. Nunes, H., "RFC-ATF-2: Runtime Governance Continuity," OMNIX QUANTUM, May 2026
5. Nunes, H., "RFC-ATF-3: Governance Policy Interoperability, Evidence Lifecycle, Forensic Verification," OMNIX QUANTUM, DOI 10.5281/zenodo.20247342, May 2026
6. EU AI Act (Regulation 2024/1689), European Parliament, 2024
7. NIST AI Risk Management Framework (AI RMF 1.0), NIST, 2023
8. ISO/IEC 42001:2023 — Artificial Intelligence Management Systems

---

## Author's Address

Raheem Larry Babatunde
VeriSigil AI
Lagos, Nigeria
raheem@verisigilai.com
verisigilai.com
