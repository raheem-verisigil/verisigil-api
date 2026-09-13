# VeriSigil Phase 2 Engineering Specification
## From Partial → Complete: 17 Refinements

**Status: DEFERRED — begins after Alkama Run 8 closes P1-A**  
**Architecture freeze in effect until P1-A confirmed**  
**No new terminology — all terms are existing VeriSigil vocabulary**  
**PRODUCTION_CLAIM_ALLOWED: False**

---

## Governing Principle

> VERISIGIL DOES NOT ESTABLISH TRUST BY ASSERTION.  
> VERISIGIL ESTABLISHES WHETHER THE AUTHORITY REQUIRED FOR A SPECIFIC  
> CONSEQUENTIAL ACTION CAN BE VERIFIED UNDER THE REQUIRED CONDITIONS.

Before accepting each phase completion, answer five questions:
1. Can it be independently verified?
2. Can the exact decision be reconstructed?
3. Can authority be distinguished from identity?
4. Can historical authority be distinguished from current authority?
5. Does failure result in blocking rather than silent continuation?

If any answer is no — the phase is not complete.

---

## Priority Order (partial → complete)

### P2-01: Principal Identity Schema
**Current state:** `subject_id` string in SigilMark. No Principal record object.  
**Gap:** Cannot verify Principal status independently. Identity and Authority are not separated.  
**Required:**
```
Principal {
  principal_id: string
  identity_type: AI_AGENT | AI_SERVICE | SOFTWARE_SYSTEM | ORGANIZATION | HUMAN | DELEGATED
  issuer: string
  verification_material: string (public key)
  status: ACTIVE | SUSPENDED | REVOKED | EXPIRED
  validity_period: {from, until}
  identity_evidence: string
}
```
**Where to add:** New Supabase table `principals`. Reference `principal_id` in SigilMark as `principal_id` alongside existing `subject_id`.  
**Test:** Unknown principal → block. Suspended principal → block. Valid principal → proceed.  
**Does not replace:** `subject_id` in existing SigilMarks. Additive only.

---

### P2-02: Authority Record Schema
**Current state:** `treasury_mandates` table (line 45688) has `ceiling`, `authorized_vendors`, `status`, `valid_until`. No formal Authority Record schema.  
**Gap:** treasury_mandates is one implementation. The Authority Record concept needs a canonical schema that any mandate type maps to.  
**Required:**
```
AuthorityRecord {
  authority_id: string
  principal_id: string
  issuer: string
  granted_authority: string
  purpose: string
  scope: string[]
  permitted_actions: string[]
  restricted_actions: string[]
  conditions: Conditions
  effective_from: datetime
  expires_at: datetime
  status: PENDING | ACTIVE | SUSPENDED | EXPIRED | REVOKED | INVALID
  evidence: string
  signature: string
}
```
**Where to add:** `VGS-AUTHORITY-RECORD-1.0` schema added to doctrine. `treasury_mandates` becomes one concrete implementation.  
**Test:** No authority → block. Expired authority → block. Wrong scope → block.

---

### P2-03: Operating Conditions as First-Class Object
**Current state:** Conditions scattered across `governing_conditions` checks and `consequence_envelope`. Not a named schema object.  
**Gap:** Conditions cannot be independently verified or reconstructed.  
**Required:**
```
OperatingConditions {
  schema: "VGS-CONDITIONS-1.0"
  time_window: {from, until}
  identity_state: string
  system_state: string
  permission_state: string
  transaction_limits: {amount, currency, period}
  required_evidence: string[]
  geographic_restrictions: string[]
  risk_threshold: string
  human_approval_required: boolean
  conditions_hash: string
}
```
**Where to add:** Add to `vcb_decision` payload and SigilMark as `operating_conditions` field.  
**Existing:** `consequence_envelope.ceiling` and `consequence_envelope.authorized_actions` already implement two condition types. This formalizes them.

---

### P2-04: Authority State Machine Formalized
**Current state:** `status TEXT DEFAULT 'ACTIVE'` in treasury_mandates (line 981). ACTIVE/REVOKED/EXPIRED exist but are not a formal state machine with transition rules.  
**Gap:** No formal transition rules. No event that triggers state change is recorded.  
**Required state transitions:**
```
PENDING → ACTIVE (on activation)
ACTIVE → SUSPENDED (on suspension event)
ACTIVE → EXPIRED (on expiry)
ACTIVE → REVOKED (on revocation)
SUSPENDED → ACTIVE (on reinstatement)
SUSPENDED → REVOKED (on revocation)
EXPIRED → INVALID (permanent)
REVOKED → INVALID (permanent)
```
**Rule:** Historical authority must not automatically become current authority.  
**Test:** Revoked authority → STILL_FAILED → REFUSE. Confirmed V4 (CA-02, 11/11 STILL suite).  
**Add:** State transition log in Supabase. `authority_state_changed_at` and `authority_state_reason` fields.

---

### P2-05: Material Change Detection
**Current state:** Owner continuity (F-32, line 45789) catches owner change → `OWNER_CONTINUITY_NOT_ESTABLISHED`.  
**Gap:** Only owner change is detected. Other material changes (model version, tool, permission scope, policy hash) do not trigger revalidation.  
**Required — named Material Change types:**
```
PRINCIPAL_CHANGED
AUTHORITY_CHANGED
DELEGATION_CHANGED
MODEL_IDENTITY_CHANGED
MODEL_VERSION_CHANGED
TOOL_CHANGED
PERMISSION_CHANGED
REQUIRED_CONDITION_CHANGED
HUMAN_APPROVAL_CHANGED
EXECUTION_ENVIRONMENT_CHANGED
AUTHORITY_EXPIRED
AUTHORITY_REVOKED
```
**When material change occurs:** Current authority → CHANGE_DETECTED → REVALIDATION → ADMISSIBLE / NOT ADMISSIBLE.  
**Add:** `material_change_detector()` function. Extend `evaluate_release()` to call it before STILL check.

---

### P2-06: Consequence Record
**Current state:** `reconciliation.implementation_status = "NOT_IMPLEMENTED — requires real actuator (P4)"` (line 96451). Field is present, not populated.  
**Gap:** Execution evidence ≠ consequence. VeriSigil currently stops at "actuator was called."  
**Required:**
```
ConsequenceRecord {
  schema: "VGS-CONSEQUENCE-1.0"
  authorized_action_hash: string
  expected_consequence: {type, amount, recipient, timestamp}
  observed_consequence: {type, amount, recipient, timestamp, reference}
  consequence_source: string
  consequence_verified_by: string
  reconciliation_result: MATCH | MISMATCH | PARTIAL | NOT_YET_OBSERVABLE
  consequence_evidence_hash: string
}
```
**Existing:** `reconciliation` field in SigilMark already has the schema. Needs real actuator (Paystack sandbox) to populate.  
**Dependency:** Requires real Paystack test transaction (P3 in current roadmap).

---

### P2-07: Authority Chain Validation
**Current state:** `parent_sigilmark_id` tracks one hop. `delegation_issue` checks parent→child.  
**Gap:** Multi-hop chain (Organization→Human→Agent→Tool) not validated end-to-end.  
**Required:**
```
validate_authority_chain(leaf_principal_id) →
  chain: [Principal, Authority, Delegation, ...Delegation, ActionRequest]
  chain_valid: boolean
  broken_link: string | null
  chain_depth: integer
```
**Test:** Full 3-hop chain valid → ALLOW. Any hop revoked → REFUSE. Fabricated intermediate → REFUSE.

---

### P2-08: VeriSigil Record (Complete Lifecycle)
**Current state:** SigilMark covers Decision→Receipt. Principal and Consequence gaps (P2-01, P2-06).  
**Gap:** Cannot reconstruct the full chain: Principal→Authority→Delegation→Action→Decision→Execution→Consequence from a single record.  
**Required:** After P2-01 and P2-06 are complete, the VeriSigil Record becomes:
```
VeriSigilRecord {
  principal: Principal
  authority: AuthorityRecord
  delegation: DelegationRecord | null
  conditions: OperatingConditions
  action_request: ActionRequest
  evaluation: AuthorityEvaluation
  decision: SigilMark
  execution: ExecutionEvidence
  consequence: ConsequenceRecord
  integrity: {hash, signature, timestamp}
  status: lifecycle_status
  verification: IndependentVerificationResult
}
```

---

### P2-09: API Alignment with Domain Model
**Current state:** Routes exist for `/v1/treasury/mandate/*`, `/v1/still/*`, `/v1/vcb/*`, `/v1/delegation/*`. Not aligned with Principal/Authority/Conditions schema.  
**Gap:** API surface reflects implementation, not domain model.  
**Required additions (after P2-01/02/03):**
```
POST /v1/principals/register
GET  /v1/principals/{id}/status
POST /v1/authorities/register
GET  /v1/authorities/{id}
GET  /v1/authorities/{id}/state
POST /v1/conditions/validate
GET  /v1/verisigil-record/{sigilmark_id}
```
**Rule:** All new endpoints must follow VeriSigil domain model naming. No external terminology in route names.

---

### P2-10: Database Relational Chain
**Current state:** `sigilmarks` and `treasury_mandates` in Supabase. Not relationally linked.  
**Gap:** Cannot query: "show me everything that established why this action was allowed."  
**Required Supabase schema additions:**
```sql
CREATE TABLE principals (
  principal_id TEXT PRIMARY KEY,
  identity_type TEXT,
  status TEXT DEFAULT 'ACTIVE',
  verification_material TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE authority_records (
  authority_id TEXT PRIMARY KEY,
  principal_id TEXT REFERENCES principals(principal_id),
  status TEXT DEFAULT 'ACTIVE',
  scope JSONB,
  expires_at TIMESTAMP,
  signature TEXT
);

CREATE TABLE authority_state_log (
  log_id TEXT PRIMARY KEY,
  authority_id TEXT REFERENCES authority_records(authority_id),
  old_status TEXT,
  new_status TEXT,
  changed_at TIMESTAMP DEFAULT NOW(),
  reason TEXT
);
```

---

### P2-11: Passport as Live Authority State
**Current state:** Passport concept exists in codebase. Not a live authority state document.  
**Gap:** Passport should expose CURRENT_AUTHORITY: ACTIVE with scope and conditions — not a static certificate.  
**Required:**
```
GET /v1/passport/{principal_id}
→ {
    principal: Principal,
    current_authority: AuthorityRecord,
    current_scope: string[],
    delegation_chain: DelegationRecord[],
    conditions: OperatingConditions,
    effective_period: {from, until},
    last_evaluation: datetime,
    verification_state: VERIFIED | UNVERIFIABLE | EXPIRED
  }
```
**Rule:** Passport never says just "AUTHORIZED." It says "CURRENT_AUTHORITY: ACTIVE" with the relevant scope and conditions.

---

### P2-12: Lifecycle State Machine in Tests
**Current state:** STILL tests authority state. Full lifecycle state machine not persisted or formally tested.  
**Add to proof suite:**
```
LSM-01: PENDING → ACTIVE transition confirmed
LSM-02: ACTIVE → REVOKED → STILL_FAILED confirmed (CA-02 already passes this)
LSM-03: ACTIVE → EXPIRED → STILL_FAILED confirmed (AP-05b already passes this)
LSM-04: REVOKED → INVALID (permanent, cannot be reinstated)
LSM-05: State transition log entry created on each change
LSM-06: Historical authority record survives state change (append-only)
```

---

### P2-13 through P2-17: Remaining Partials
These require P2-01 through P2-06 to be complete first:

| ID | Item | Dependency |
|----|------|------------|
| P2-13 | Evidence distinction (authority/decision/execution/consequence) | P2-06 Consequence Record |
| P2-14 | Execution evidence ≠ consequence formally separated | P2-06 + real actuator |
| P2-15 | 5-question gate applied to every new endpoint | All P2 phases |
| P2-16 | API domain model alignment complete | P2-01/02/03 |
| P2-17 | Full testing strategy covering all 32 test types | All P2 phases |

---

## What Does NOT Change

The architecture freeze protects:

- VCB terminology (STILL, COULD, WHAT, SigilMark, ConsequenceCommitment)
- The locked claim language in CLAIMS_REGISTRY.md
- PRODUCTION_CLAIM_ALLOWED = False
- The existing proof record (V3-V5 evidence)
- The 9-point engineering invariant list in existing doctrine
- The architecture: no new product surfaces until Phase 2 is proven

---

## Build Order After Alkama Run 8

```
P1-A closes (Alkama Run 8)
    ↓
P2-01: Principal Identity Schema
    ↓
P2-02: Authority Record Schema
    ↓
P2-03: Operating Conditions Schema
    ↓
P2-04: Authority State Machine
    ↓
P2-05: Material Change Detection
    ↓
P2-06: Consequence Record (requires real actuator)
    ↓
P2-07: Authority Chain Validation
    ↓
P2-08: VeriSigil Record (complete lifecycle)
    ↓
P2-09/10: API + Database alignment
    ↓
P2-11: Passport as live authority state
    ↓
P2-12/17: Lifecycle tests + remaining partials
    ↓
EVALUATE PRODUCTION_CLAIM_ALLOWED
```

---

*PRODUCTION_CLAIM_ALLOWED: False*  
*This specification requires no new code until Alkama Run 8 confirms P1-A*  
*All 17 refinements use existing VeriSigil terminology only*
