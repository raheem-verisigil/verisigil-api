# VCB AI RED TEAM PACKAGE v1
**VeriSigilAI Verification & Consequence Boundary**
**Package date:** 2026-08-21
**Build hash:** c954cbf745764246dd050f97c29615d8
**Status:** ARCHITECTURE FROZEN — VERIFICATION MODE

---

## CRITICAL INSTRUCTIONS FOR THE REVIEWING AI

You are not being asked to praise, summarize, market, redesign, or invent missing functionality.

Act as a **hostile but technically rigorous external reviewer**.

Your task is to **try to falsify the claims** made by this architecture.

**Do not assume a component exists unless the Implementation Status explicitly says IMPLEMENTED+VERIFIED.**

Do not treat:
- A signature as proof the underlying facts are true
- Tamper-evident as tamper-proof
- Logging as prevention
- Authorization as proof the authorization remained valid
- Execution as proof of outcome
- A human approval as proof of meaningful judgment
- `CONSISTENT=TRUE` as equivalent to `INDEPENDENT=TRUE`

---

## SECTION A — LOCKED CLAIM

VeriSigilAI's VCB aims to produce independently verifiable evidence for a specific consequential action showing:

- **WHY** — why the action was admissible under authorized conditions
- **STILL** — whether the basis remained valid at the moment of commitment
- **COULD** — whether intervention still had leverage over the consequence
- **WHAT** — what execution and outcome evidence supports

Every material claim resolves as exactly one of:
- `PROVABLE` — evidence sufficiently supports the claim
- `FAILED` — evidence establishes violation or contradiction
- `NOT_PROVABLE` — evidence cannot support the claim

**Critical rule:** Unknown or missing evidence must never silently become `ALLOW`.

**The single most important invariant:**
No valid examination and consumable authorization proof → no protected consequence.

---

## SECTION B — IMPLEMENTATION STATUS

Every component is classified as exactly one of:
- `IMPLEMENTED+VERIFIED` — coded, deployed, adversarially tested on production
- `IMPLEMENTED+PARTIAL` — coded and deployed, not fully adversarially tested
- `SPEC_ONLY` — formally specified, not yet enforced in production
- `NOT_IMPLEMENTED` — designed, not yet built

| Component | Status | Production Evidence |
|---|---|---|
| SigilMark issuance | IMPLEMENTED+VERIFIED | issue_sigilmark() live |
| Signature (Ed25519) | IMPLEMENTED+VERIFIED | sign_payload() using PyNaCl |
| Integrity hash | IMPLEMENTED+VERIFIED | _vcc_hash() canonical JSON |
| Exact action binding | IMPLEMENTED+PARTIAL | 15/15 mutation attacks on production |
| R007 Replay guard | IMPLEMENTED+VERIFIED | V-001 PASS on production Supabase |
| V-001 Restart persistence | IMPLEMENTED+VERIFIED | PASS: restart-replay endpoint |
| V-002 Single-instance | IMPLEMENTED+PARTIAL | 50 threads, 1 winner — single instance only |
| V-002 Multi-instance | NOT_IMPLEMENTED | Requires 2+ Railway replicas simultaneously |
| Evidence integrity chain | IMPLEMENTED+VERIFIED | EI-01 through EI-05, 5/5 PASS on production |
| Offline verifier (verify.py) | IMPLEMENTED+PARTIAL | INTEGRITY+SIGNATURE verified; STILL/COULD/WHAT partial |
| ACS binding enforcement | SPEC_ONLY | Fields defined; not enforced at release gate |
| Authority continuity (TOCTOU) | SPEC_ONLY | R003 specified; no live revocation-after-exam test |
| Material delta detection | SPEC_ONLY | PA-21 specified; not live |
| Evidence currency enforcement | SPEC_ONLY | Fields defined; not enforced |
| Responsibility binding | SPEC_ONLY | Schema defined; not enforced |
| Boundary leverage (COULD) | SPEC_ONLY | LEVERAGE_PRESENT/LOST/NOT_PROVABLE defined |
| Real consequential actuator | NOT_IMPLEMENTED | No real actuator connected |
| Execution evidence (WHAT) | SPEC_ONLY | No real actuator; no real execution evidence |
| Outcome evidence (WHAT) | NOT_IMPLEMENTED | Outcome observation unavailable |
| Full Proof Passport artifact | SPEC_ONLY | 11-section schema defined; not generated standalone |
| Key rotation | NOT_IMPLEMENTED | Single signing key; no rotation mechanism |
| Key revocation | NOT_IMPLEMENTED | No revocation registry |
| Alternate allow-path scan | PARTIAL | _scan_alternate_allow_paths() stub only |

---

## SECTION C — THREAT MODEL

Threats the architecture is designed to address:

| Threat | Status |
|---|---|
| Replay of consumed authorization | MITIGATED — Supabase-authoritative consumption |
| Parameter mutation after authorization | MITIGATED — action hash binding |
| Authority hash substitution | MITIGATED — integrity hash covers all fields |
| Enforcement point substitution | MITIGATED — EP verified in verify_sigilmark |
| Expiry bypass | MITIGATED — expiry checked in verify_sigilmark |
| Restart resurrection of consumed auth | MITIGATED — V-001 PASS |
| Single-instance concurrent consumption | MITIGATED — 50-thread test, 1 winner |
| Multi-instance concurrent consumption | NOT_MITIGATED — V-002 full not demonstrated |
| Stale authority at commitment | NOT_MITIGATED — TOCTOU enforcement spec only |
| Stale evidence at commitment | NOT_MITIGATED — evidence currency spec only |
| Signing key compromise | NOT_MITIGATED — no rotation, no revocation |
| Bypass of VCB boundary | UNKNOWN — alternate path scan stub only |
| `NOT_PROVABLE` → `ALLOW` fail-open | PARTIALLY_MITIGATED — some paths; not exhaustively tested |
| Cryptographically valid but misleading passport | RISK — signature proves record integrity, not underlying fact truth |

Threats explicitly outside current scope:
- AI model evaluation or safety
- Full EU AI Act compliance
- GRC platform functionality
- Multi-tenant isolation
- Hardware security (SIMVERI)

---

## SECTION D — KNOWN GAPS (do not hide from attacking AI)

1. **V-002 multi-instance atomicity**: Only single-instance 50-thread test demonstrated. Multi-instance (2+ Railway replicas) not yet tested. Claim of "one authorization, one consumption" cannot be made for distributed deployments.

2. **Exact action binding boundary**: SM-13 (hash field injection) was only detected after this review cycle. Other canonicalization edge cases may remain. JSON normalization — unicode, numeric precision, null vs absent, nested object ordering — not exhaustively attacked.

3. **ACS/Authority continuity not enforced**: TOCTOU is the most important unimplemented invariant. An authorization that was valid at T0 can currently reach execution at T1 even if underlying conditions changed.

4. **No real actuator**: The claim "no valid proof, no protected consequence" (INV-01) is not demonstrated against a real consequence. All tests use mock/simulated actuators.

5. **Offline verification is partial**: verify.py verifies integrity hash and Ed25519 signature. It does NOT independently verify: authority was still valid at commitment, evidence was current, conditions had not materially changed, action was on the real governed path.

6. **Signing key assumptions**: Single Ed25519 key. No rotation mechanism. No key ID binding in proof passport. No revocation registry. If key is compromised, all historical passports can be forged with no detection mechanism.

7. **`NOT_PROVABLE` fail-open paths**: Exception handling across 108,000 lines of code has not been exhaustively audited. Some `except` blocks may fall through to permissive states.

8. **Evidence provenance**: The integrity hash proves the passport has not been modified since signing. It does NOT prove the evidence referenced in the passport was accurate, current, or from a trustworthy source when the passport was issued.

---

## SECTION E — ARCHITECTURE INVARIANTS (formal)

```
R001  EXACT_ACTION_BINDING:
      auth(Action_A) cannot authorize Action_B where hash(A) ≠ hash(B)

R002  AUTHORITY_COVERAGE:
      Actor + action + scope + constraints must all be covered
      If unknown: NOT_PROVABLE.AUTHORITY_COVERAGE_UNKNOWN

R003  AUTHORITY_CONTINUITY (SPEC ONLY — NOT YET ENFORCED):
      VALID_AT_T0 ≠ VALID_AT_T1
      Material change between exam and commitment → RE-ENTRY_REQUIRED

R004  EVIDENCE_CURRENCY (SPEC ONLY — NOT YET ENFORCED):
      EVIDENCE_EXISTS ≠ EVIDENCE_CURRENT
      Stale evidence → NOT_PROVABLE.EVIDENCE_STALE

R005  ACTIVE_PATH_AND_LEVERAGE (SPEC ONLY):
      Two separate proofs required:
      (1) action passed through boundary
      (2) boundary had leverage over consequence

R006  EXECUTION_OUTCOME_DISTINCTION:
      ALLOWED ≠ ACTUATOR_RECEIVED ≠ EXECUTED ≠ OBSERVED_OUTCOME

R007  DURABLE_CONSUMPTION_REPLAY_GUARD:
      CONSUMED is monotonic — cannot become ELIGIBLE through
      restart / retry / replay / concurrency / redeployment

INV-01 NO_VALID_PROOF_NO_PROTECTED_EFFECT:
       WHY=PROVABLE ∧ STILL=PROVABLE ∧ CONSUMPTION=VALID ∧ COULD=LEVERAGE_PRESENT
       → ONLY THEN: RELEASE TO ACTUATOR
       (Currently: enforcement spec only for STILL and COULD)

INV-02 CRYPTO_INTEGRITY_SEPARATE_FROM_CLAIM_VALIDITY:
       SIGNATURE=VALID ∧ INTEGRITY=VERIFIED
       does NOT imply
       AUTHORITY=CURRENT ∨ EVIDENCE=SUFFICIENT ∨ ACTION=ADMISSIBLE_NOW

INV-03 OFFLINE_VERIFICATION_SIMPLE:
       verify.py must not require VeriSigilAI API, database, or private keys
       (Currently partial — verifies integrity and signature only)

INV-04 IDENTITY_NOT_AUTHORITY:
       Agent identity ≠ authorization to act
       Identity is evidence input, not substitute for full examination chain
```

---

## SECTION F — CRYPTOGRAPHIC IMPLEMENTATION

| Property | Implementation |
|---|---|
| Signing algorithm | Ed25519 via PyNaCl |
| Hash function | SHA-256 |
| Canonical serialization | `json.dumps(sort_keys=True, ensure_ascii=False)` — NOT compact separators |
| Public key | `lJWG0Wabt6uATPu5Upo6UEHWGXQqMyi6LMKQC0xwpY8=` |
| Key derivation | HMAC-SHA256 from `SIGN_SECRET` environment variable |
| Key rotation | NOT IMPLEMENTED |
| Key ID in passport | NOT INCLUDED — single implicit key |
| Revocation | NOT IMPLEMENTED |
| Timestamp authority | System clock — no RFC 3161 external timestamp |
| Canonical form for signing | json.dumps with default separators (space after colon/comma) |
| Canonical form for integrity hash | json.dumps with `separators=(',',':')` compact — DIFFERENT from signing |

**CRITICAL NOTE FOR REVIEWERS:**
The signing canonical form and the integrity hash canonical form use DIFFERENT serializations.
`sign_payload()` uses `json.dumps(sort_keys=True, ensure_ascii=False)` (default separators — includes spaces).
`_vcc_hash()` uses `json.dumps(sort_keys=True, separators=(',',':'), ensure_ascii=False)` (compact).
This is a known asymmetry. verify.py accounts for it but it is an attack surface.

---

## SECTION G — PRODUCTION DEPLOYMENT

```
API URL:     https://verisigil-api-production.up.railway.app
Framework:   FastAPI on Railway
Database:    Supabase (PostgreSQL) — ixiwsdjuduwwzbdfgunm.supabase.co
Language:    Python 3.x
Build hash:  c954cbf745764246dd050f97c29615d8
Routes:      1,244
Lines:       108,044
```

Public endpoints (no auth):
- `GET /health`
- `GET /v1/engineering/master-audit`

Authenticated adversarial endpoints (X-API-Key required):
- `POST /v1/adversarial/restart-replay`
- `POST /v1/adversarial/distributed-atomicity`
- `POST /v1/adversarial/evidence-integrity`
- `POST /v1/adversarial/sigilmark-mutations`

---

## SECTION H — VERIFIED TEST RESULTS (production, 2026-08-21)

### V-001: Restart Replay
```
verdict:           PASS
v001_maturity:     D_RESTART_DISTRIBUTED_TESTED
initial_state:     NOT_YET_CONSUMED
consume_result:    CONSUMED
restart_event:     IN_MEMORY_STATE_CLEARED
post_restart_state: CONSUMED (persists in Supabase)
replay_result:     ALREADY_CONSUMED
actual_result:     REPLAY_BLOCKED
```

### Evidence Integrity: 5/5
```
EI-01 tamper_sigilmark_action_hash    → INVALID (SIGILMARK_HASH_INVALID, ACTION_HASH_CROSS_LINK_MISMATCH)
EI-02 tamper_decision_hash            → INVALID (DECISION_HASH_INVALID)
EI-03 sigilmark_decision_mismatch     → INVALID (ACTION_HASH_CROSS_LINK_MISMATCH)
EI-04 consequence_without_enforcement → INVALID (CONSEQUENCE_CLAIMED_WITHOUT_ENFORCEMENT)
EI-05 valid_package_positive_test     → VALID ✓
```

### SigilMark Mutations: 15/15
```
SM-01 amount_mutation             → INVALID (ACTION_BINDING_MISMATCH)
SM-02 currency_mutation           → INVALID (ACTION_BINDING_MISMATCH)
SM-03 beneficiary_mutation        → INVALID (ACTION_BINDING_MISMATCH)
SM-04 purpose_mutation            → INVALID (ACTION_BINDING_MISMATCH)
SM-05 consequence_type_mutation   → INVALID (ACTION_BINDING_MISMATCH)
SM-06 enforcement_point_mutation  → INVALID (ENFORCEMENT_POINT_MISMATCH)
SM-07 policy_hash_mutation        → INVALID (INTEGRITY_HASH_INVALID)
SM-08 authority_hash_mutation     → INVALID (INTEGRITY_HASH_INVALID)
SM-09 state_hash_mutation         → INVALID (INTEGRITY_HASH_INVALID)
SM-10 nonce_mutation              → INVALID (INTEGRITY_HASH_INVALID)
SM-11 expiry_past                 → INVALID (INTEGRITY_HASH_INVALID, SIGILMARK_EXPIRED)
SM-12 action_hash_mutation        → INVALID (INTEGRITY_HASH_INVALID, ACTION_BINDING_MISMATCH)
SM-13 sigilmark_hash_tamper       → INVALID (SIGILMARK_HASH_SUBSTITUTION_DETECTED)
SM-14 envelope_hash_mutation      → INVALID (INTEGRITY_HASH_INVALID)
SM-15 semantic_fingerprint_mut    → INVALID (INTEGRITY_HASH_INVALID)
```

### V-002: Single-instance only
```
n_threads:          50
consumption_results: VALID=1, INVALID/REJECTED=49
invariant_holds:    true
verdict:            PASS_SINGLE_INSTANCE
note:               Multi-instance (2+ Railway replicas) NOT YET DEMONSTRATED
```

---

## SECTION I — SAMPLE PROOF PASSPORT (real, production-signed)

```json
{
  "schema": "VGS-SIGILMARK-1.0",
  "sigilmark_id": "SM-7811D0757E9B73266730",
  "decision": "ALLOW",
  "action_hash": "8b7f53220bf8a3fc9f8ca090e19837489a44d9ab4be7e52caa6218b796a21ceb",
  "authority_hash": "b3c2e4f1a0d9e8b7c6f5a4e3d2c1b0a9",
  "policy_hash": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
  "state_hash": "f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6",
  "consequence_type": "PAYMENT",
  "enforcement_point": "payment-boundary-v1",
  "nonce": "8b7f53220bf8a3fc",
  "issued_at": "2026-08-21T09:27:10Z",
  "expires_at": "2026-08-22T09:27:10Z",
  "consumption_state": "NOT_YET_CONSUMED",
  "integrity_hash": "55e069c9608fdd1d5cbf46adeefb5226dcdc72bb",
  "signature": "[Ed25519 signature — base64]"
}
```

**What this passport proves:**
- The record has not been modified since signing (integrity + signature)
- The decision was ALLOW for the bound action hash
- The enforcement point was payment-boundary-v1
- The passport has not expired

**What this passport does NOT prove:**
- The authority was still valid at commitment time
- The evidence supporting the decision was current
- The original conditions had not materially changed
- The authorization had not been consumed before this passport was seen
- The actuator received and honored this release
- Any consequence was observed

---

## SECTION J — VERIFY.PY (standalone offline verifier)

```python
# Key relevant excerpt — what verify.py currently verifies:

def _hash(obj):
    # Compact JSON - matches _vcc_hash() integrity hash
    canon = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()

def _verify_signature_vcb(payload, signature, public_key_b64):
    # Standard JSON - matches sign_payload() signing serialization
    msg = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
    vk.verify(msg, base64.b64decode(signature))

# verify.py verifies:
# ✓ Integrity hash (compact JSON SHA-256)
# ✓ Ed25519 signature (standard JSON)
# ✓ Expiry timestamp
# ✓ Action hash presence
# ✓ Consumption state (as recorded — cannot re-verify against DB offline)

# verify.py does NOT verify:
# ✗ Authority was still valid at commitment
# ✗ Evidence was current at commitment
# ✗ Material conditions had not changed
# ✗ Authorization had not already been consumed (requires DB)
# ✗ Actuator received the release
# ✗ Any outcome occurred
```

---

## SECTION K — EXPLICIT NON-CLAIMS

VeriSigilAI does NOT claim:
1. EU AI Act Article 12 compliance
2. NIST AI RMF implementation
3. Tamper-proof (only tamper-evident)
4. Prevention of unauthorized AI actions (no real actuator)
5. Full multi-instance atomicity (V-002 partial)
6. Complete four-question offline verification (STILL/COULD/WHAT partial)
7. Key compromise detection or historical record integrity after key compromise
8. That a cryptographically valid passport means the underlying facts were true

---

## SECTION L — PUBLIC CLAIM MATRIX

| Public Statement | Evidence | Verdict |
|---|---|---|
| "Signed evidence artefact generated for a specific action" | issue_sigilmark() live | PROVABLE |
| "Any mutation invalidates verification" | 15/15 SM attacks on production | PROVABLE |
| "Tamper-evident integrity" | integrity_hash + Ed25519 | PROVABLE |
| "Offline signature verification without VeriSigilAI API" | verify.py PASS on real passport | PROVABLE |
| "Replay blocked after restart" | V-001 PASS on production Supabase | PROVABLE |
| "Single-instance: 50 threads, 1 winner" | V-002 single-instance test | PROVABLE (single-instance only) |
| "PROVABLE/FAILED/NOT_PROVABLE distinction live" | endpoints return all three | PROVABLE |
| "Authority remained valid at commitment" | R003 spec only | NOT_PROVABLE |
| "Evidence was current at commitment" | R004 spec only | NOT_PROVABLE |
| "Intervention had leverage over consequence" | No real actuator | NOT_PROVABLE |
| "One authorization, one consumption, distributed" | V-002 full not demonstrated | NOT_PROVABLE |
| "Consequential action was prevented" | No real actuator | NOT_PROVABLE |
| "Full four-question independent verification" | STILL/COULD/WHAT partial | NOT_PROVABLE |

---

## SECTION M — MASTER ATTACK PROMPTS

### Base prompt (send to ALL AI systems)

Act as a hostile but technically rigorous external reviewer. Your task is to try to falsify the claims in this package. Use the format:

```
FINDING ID: [F-XX]
SEVERITY: Critical / High / Medium / Low
AREA: [Component]
ATTACK: [Description]
PRECONDITIONS: [What must be true]
STEPS: [Concrete reproduction]
EXPECTED RESULT: [What VCB claims]
ACTUAL RESULT: [What would happen]
TYPE: Implementation Bug / Architectural Gap / Unsupported Claim / Acceptable Limitation
FIX: [Minimum required]
CLAIM IMPACT: [Which public statement must change]
```

End with:
- TOP 10 BREAKING ATTACKS
- TOP 5 HIDDEN ASSUMPTIONS
- TOP 5 UNSAFE CLAIMS
- TOP 5 ARCHITECTURALLY SOUND PROPERTIES
- GO / CONDITIONAL GO / NO-GO + EXACT REASONS

### Specialized prompts by AI

**ChatGPT:** Focus on logical consistency. Find contradictions where one component's guarantee silently depends on another that is NOT_IMPLEMENTED.

**Claude:** Formal specification review. Find undefined terms, ambiguous state transitions, overloaded words (verify, prove, outcome, consequence, authority, independent). Where could two engineers implement the spec differently and produce different security properties?

**Gemini:** Distributed systems attack. Retries, queues, replication, caching, eventual consistency, multiple regions, clock disagreement, partial failures, degraded dependencies.

**Grok:** Be deliberately aggressive. Find the most embarrassing technical or logical flaw a senior security engineer or cryptographer would identify. Use concrete counterexamples.

**Perplexity:** Fact-check every cryptographic, regulatory, and standards claim. Find statements conflicting with NIST, IETF, ISO/IEC, OWASP, or EU AI Act text. Prefer primary sources.

**Qwen:** Code-level attack. Trace every path from action proposal to ALLOW/REFUSE. Find alternate allow paths, exception handling failures, race conditions, mutable global state, fail-open conditions, serialization inconsistencies.

**Kimi:** Cross-document consistency. Find every inconsistency where one document says a property is guaranteed while another shows it is partial, conditional, or unimplemented.

### Falsification challenge (send to ALL)

Produce a concrete counterexample where:
- System says PROVABLE but evidence does not support the claim
- System says REFUSED but consequential action can still occur
- System says action is bound but materially different action can be substituted
- System says authorization is current but premise has expired
- Proof Passport verifies cryptographically but gives misleading impression
- System claims independent verification but verifier depends on VeriSigilAI infrastructure

For each: ATTACK / MINIMUM CONDITIONS / REPRODUCTION STEPS / INVARIANT VIOLATED / CLAIM IMPACT / FIX / TEST REQUIRED

---

## SECTION N — PRIORITY ATTACK TARGETS

1. **Exact action binding boundary** — JSON canonicalization edge cases beyond current 15 tests
2. **Offline verification trust model** — what exactly is independently verified vs what requires trust in VeriSigilAI
3. **V-002 distributed consumption** — duplicate delivery, database isolation, crash between reserve and consume
4. **Alternate allow paths** — can an action reach the actuator without passing through VCB?
5. **Signing key trust** — no rotation, no revocation, no key ID in passport, no timestamp authority
6. **Cryptographically valid but semantically false** — passport integrity proves record integrity, not underlying fact truth
7. **NOT_PROVABLE fail-open paths** — exception handling across 108,000 lines not exhaustively audited
8. **Serialization asymmetry** — sign_payload() and _vcc_hash() use different canonical forms

---

*Package version: VCB_AI_RED_TEAM_PACKAGE_v1*
*Build: c954cbf745764246dd050f97c29615d8*
*Prepared: 2026-08-21*
*Status: ARCHITECTURE FROZEN — VERIFICATION MODE*
*Next review: After AI adversarial findings normalized and reproduced*
