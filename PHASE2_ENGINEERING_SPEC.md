
---

## P2-05 EXTENSION: Temporal Standing — Live Authority Re-Derivation

**Added:** Sep 20 2026  
**Triggered by:** Tim Zlomke Temporal Standing Test examination  
**Priority:** HIGH — named architectural gap, externally identified

### The Gap

Current delegation endpoint reads parent scope/ceiling from the sealed SigilMark (`consequence_envelope` in the immutable artifact). A change to the underlying authority after T₀ — ceiling reduction, scope removal, revocation — is not reflected at Tₙ.

This means the delegation path enforces against T₀ state, not current authoritative state.

### Required Engineering

The delegation endpoint needs a live mandate re-query path:

```python
# Current (reads sealed artifact):
envelope = parent_sm.get("consequence_envelope") or {}
parent_ceiling = envelope.get("ceiling")
parent_scope = envelope.get("authorized_actions") or []

# Required (re-derives from live mandate):
if req.get("require_live_authority", False) or DELEGATION_LIVE_REQUERY_DEFAULT:
    live_mandate = await get_live_mandate(parent_sm.get("authority_id"))
    if live_mandate.get("found"):
        parent_ceiling = live_mandate["mandate"].get("ceiling")
        parent_scope = live_mandate["mandate"].get("authorized_actions") or []
        parent_status = live_mandate["mandate"].get("status")
        if parent_status != "ACTIVE":
            return REFUSE(reason="PARENT_AUTHORITY_NO_LONGER_ACTIVE")
```

### Tim's Paired Test Structure (to run after this is built)

**T₀:** Parent sealed with scope `["read_document"]` ceiling `1000`  
**Same child in both branches:** `["read_document"]` ceiling `500`

**ΔN₁ (standing-preserving):** Parent ceiling changes `1000 → 750`  
→ Expected: ISSUE (child 500 ≤ new ceiling 750 ✓)

**ΔN₂ (standing-defeating):** Parent ceiling changes `1000 → 400`  
→ Expected: REFUSE (child 500 > new ceiling 400 ✗)

**Proposition to freeze:**  
"For the same consequential child action, VeriSigil distinguishes a standing-preserving change from a standing-defeating change in authoritative parent state before consequence binds."

**Falsifier:**  
If both ΔN branches return the same result, or if the system requires the verdict supplied externally — NOT ESTABLISHED.

### Evidence Discipline

- Current evidence record preserved unchanged
- Today's boundary (NOT ESTABLISHED) stays in CLAIMS_REGISTRY.md
- When built: fresh specimen under new frozen proposition
- Failed predecessor (NOT ESTABLISHED) remains in lineage — not overwritten

### Dependencies

- P2-02: Authority Record Schema (live mandate query needs an authority record)
- P2-04: Authority State Machine (live status check)
- P2-05: Material Change Detection (trigger for re-query)

Build order: P2-02 → P2-04 → P2-05 → Temporal Standing re-query → Tim's test
