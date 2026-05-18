# VGS-ATF Interoperability Specification
# Cross-Domain Authority Provenance
# VGS-012 · Draft 1.0 · 2026-05-18

## Overview

This specification defines how VeriSigil Governance Standard (VGS)
and Agent Trust Fabric (ATF) artifacts interoperate across governance
domain boundaries.

VGS DOI: https://doi.org/10.5281/zenodo.20264923
ATF RFC-ATF-1: https://doi.org/10.5281/zenodo.20155016
ATF RFC-ATF-3: https://doi.org/10.5281/zenodo.20247342

## The Core Problem

When an agent chain spans governance domains:

```
Agent A (EU jurisdiction, ATF-governed)
  → delegates to →
Agent B (US jurisdiction, VGS-governed)
  → executes on →
GCC infrastructure
```

How does a verifier reconstruct, years later and without trusting
any live platform, that Agent B's authority was legitimately derived
from Agent A's EU delegation?

## The Answer: Cross-Domain Provenance Receipt (CDPR)

A CDPR is a bridge artifact that:
- Wraps artifacts from two different governance domains
- Dual-signs using both domains' key pairs
- Creates a single canonical provenance chain
- Is verifiable offline by either domain's verifier independently

## Evidence Class Mapping

| ATF Class | VGS Class | Legal Weight          | Parity |
|-----------|-----------|----------------------|--------|
| DR        | GDR       | DELEGATION_AUTHORITY  | Semantic |
| RCR       | RCR       | CONTINUITY_PROOF      | Direct   |
| FVP       | FRI       | FORENSIC_INPUT        | Semantic |
| PVR       | PVR       | POLICY_VIOLATION      | Direct   |
| ADR       | ADR       | APPROVAL_DECISION     | Direct   |
| ATR       | ATR       | AUTHORITY_TRANSITION  | Direct   |

## Canonical Serialization Alignment

Both ATF (RFC-ATF-3 FVP-INV-007) and VGS (VER-INV-008) use
identical canonical serialization rules:

```python
json.dumps(obj,
    sort_keys=True,
    separators=(',', ':'),
    ensure_ascii=False,
    encoding='utf-8'
)
```

Cross-runtime parity verified (VEC-002):
Input:  {"user": "José", "action": "approve"}
Output: {"action":"approve","user":"José"}
Hash:   sha256:9de59918836b0c8de5568669a3a87afe...

Python and Node.js produce identical bytes. ATF-compatible.

## Revocation Semantics Differences

| Domain    | Model                    | Grace Period | Spec           |
|-----------|--------------------------|-------------|----------------|
| ATF       | EXECUTION_COUNT_BOUNDED  | 1 count     | RFC-ATF-2 §4.3 |
| EU_AI_ACT | IMMEDIATE_HARD_STOP      | 0           | Article 14     |
| US_NIST   | GRACE_PERIOD             | 24 hours    | NIST RMF       |
| CN_AI_LAW | STATE_AUTHORITY_REQUIRED | 0           | CN AI Law 2025 |
| GCC_DIFC  | IMMEDIATE_HARD_STOP      | 0           | DIFC Reg 10    |
| VGS       | SYNCHRONOUS_PROPAGATION  | 0           | VGS-011 §3.2   |

Conflict resolution: CDPR applies strictest-combination.

## CDPR Structure

```json
{
  "cdpr_id": "CDPR-A1B2C3D4",
  "cdpr_version": "VGS-012-1.0",
  "bridge_type": "ATF_to_VGS",
  "from_artifact": {
    "type": "DR",
    "id": "DR-atf-001",
    "domain": "ATF",
    "agent": "agent-A",
    "revocation": "EXECUTION_COUNT_BOUNDED"
  },
  "to_artifact": {
    "type": "GDR",
    "id": "GDR-vgs-001",
    "domain": "VGS",
    "agent": "agent-B",
    "revocation": "SYNCHRONOUS_PROPAGATION"
  },
  "provenance_chain": [
    {"step": 0, "domain": "ATF", "artifact": "DR-atf-001", "agent": "agent-A"},
    {"step": 1, "domain": "VGS", "artifact": "GDR-vgs-001", "agent": "agent-B", "parent_step": 0}
  ],
  "provenance_chain_hash": "sha256:...",
  "canonical_hash": "sha256:...",
  "revocation_conflict": false,
  "strictest_revocation": "EXECUTION_COUNT_BOUNDED",
  "verification": {
    "vgs_verifiable": true,
    "atf_compatible": true,
    "offline_verifiable": true,
    "requires_live_platform": false
  }
}
```

## Open Questions For ATF Alignment

1. When EU domain revokes Agent B's authority but Agent C is
   executing under B's delegation in the US domain — does ATF
   model this as a state transition or an event?

2. Should evidence created by Agent C during the collapse window
   be classified as PVR (sealed violation) or FRI (forensic input
   pending review)?

3. How does ATF's execution-count-bounded model interact with
   VGS's synchronous propagation when revocation crosses domains?

## Conformance Vectors (Cross-Domain)

See conformance_vectors.json VEC-081 through VEC-085.

## Status

- VGS-012 core: IMPLEMENTED (POST /v1/cdpr/issue)
- ATF bridge verifier: IMPLEMENTED (atf_bridge_verify.py)
- Cross-domain vectors: IMPLEMENTED (VEC-081 to VEC-085)
- Joint RFC: PROPOSED

## Citation

Babatunde, R. L. (2026). VeriSigil Governance Specification
(VGS-001 to VGS-011). Zenodo.
https://doi.org/10.5281/zenodo.20264923
