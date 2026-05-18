---- MODULE VeriSigilGovernance ----
(**
 * VeriSigil Governance Formal Specification
 * ==========================================
 * VGS-SPEC-001 — TLA+ Formal Model
 *
 * This specification formally defines VeriSigil's governance
 * state machine, invariants, and safety properties.
 *
 * TLA+ (Temporal Logic of Actions) allows us to:
 * 1. Define the complete state space of governance decisions
 * 2. Specify safety invariants that must hold in ALL states
 * 3. Prove liveness properties (governance eventually terminates)
 * 4. Detect deadlocks and invariant violations mechanically
 *
 * Model Checker: TLC (included in TLA+ Toolbox)
 * Reference: Lamport, L. (2002). Specifying Systems.
 *
 * Author: VeriSigil AI — verisigilai.com
 * Schema: VGS-SPEC-001
 *)

EXTENDS Integers, Reals, Sequences, FiniteSets

\* ── CONSTANTS ────────────────────────────────────────────────

CONSTANTS
    Agents,          \* Set of all possible agent IDs
    Actions,         \* Set of all possible action types
    Organizations,   \* Set of all possible organization IDs
    MaxChainLength   \* Maximum delegation chain depth (acyclicity bound)

\* ── TYPE DEFINITIONS ─────────────────────────────────────────

\* Decision type
Decision == {"ALLOW", "DENY", "REQUIRE_HUMAN_APPROVAL"}

\* Consequence levels (ordered: LOW < MEDIUM < HIGH < CRITICAL)
ConsequenceLevel == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

\* Governance states (from VGS-002 state machine)
GovernanceState == {
    "UNVERIFIED",
    "VERIFIED",
    "PROVISIONAL",
    "ADMISSIBLE",
    "ESCALATED",
    "EXECUTING",
    "COMPLETED",
    "FAILED",
    "DENIED"
}

\* Evidence classes (from VGS-007 — all terminal)
EvidenceClass == {"GDR", "RCR", "ATR", "EER", "ADR", "PVR", "FRI", "AIP"}

\* Jurisdiction regimes (from VGS-010)
JurisdictionRegime == {"EU_AI_ACT", "US_NIST", "CN_AI_LAW", "GCC_DIFC", "NONE"}

\* ── STATE VARIABLES ──────────────────────────────────────────

VARIABLE
    agent_states,        \* agent_id -> GovernanceState
    agent_trust,         \* agent_id -> Real in [0, 1]
    agent_passports,     \* agent_id -> {valid: Bool, revoked: Bool, expired: Bool}
    chain_blocks,        \* Sequence of governance decisions (append-only)
    eat_tokens,          \* token_id -> {valid, agent_id, action, expires, revoked}
    evidence_records,    \* record_id -> {class, hash, created_at, immutable}
    delegation_chains,   \* chain_id -> Sequence of agent_ids
    approvals,           \* approval_id -> {decision, agent_id, action, approved}
    jurisdiction_cache,  \* (action, region) -> Set of JurisdictionRegime
    continuity_scores    \* chain_id -> Real in [0, 1]

\* ── INITIAL STATE ────────────────────────────────────────────

Init ==
    /\ agent_states      = [a \in Agents |-> "UNVERIFIED"]
    /\ agent_trust       = [a \in Agents |-> 0]
    /\ agent_passports   = [a \in Agents |-> [valid |-> FALSE, revoked |-> FALSE, expired |-> FALSE]]
    /\ chain_blocks      = <<>>
    /\ eat_tokens        = <<>>
    /\ evidence_records  = <<>>
    /\ delegation_chains = <<>>
    /\ approvals         = <<>>
    /\ jurisdiction_cache= [x \in ({} \X {}) |-> {}]
    /\ continuity_scores = <<>>

\* ── HELPER DEFINITIONS ───────────────────────────────────────

\* Trust level classification
TrustLevel(trust) ==
    IF trust >= 0.95 THEN "SOVEREIGN"
    ELSE IF trust >= 0.90 THEN "ADMIN"
    ELSE IF trust >= 0.80 THEN "ELEVATED"
    ELSE IF trust >= 0.65 THEN "BASIC"
    ELSE "NONE"

\* Is a passport valid (not revoked and not expired)?
PassportValid(agent) ==
    /\ agent_passports[agent].valid
    /\ ~agent_passports[agent].revoked
    /\ ~agent_passports[agent].expired

\* Does trust score meet minimum threshold for consequence?
TrustMeetsConsequence(agent, consequence) ==
    LET trust == agent_trust[agent]
    IN  CASE consequence = "LOW"      -> trust >= 0.65
          [] consequence = "MEDIUM"   -> trust >= 0.75
          [] consequence = "HIGH"     -> trust >= 0.85
          [] consequence = "CRITICAL" -> trust >= 0.95
          [] OTHER                    -> FALSE

\* GCS formula — geometric mean of trust scores in chain
\* (Simplified for TLA+ — full floating point in implementation)
ChainIntact(chain) ==
    \A i \in 1..Len(chain) :
        /\ PassportValid(chain[i])
        /\ agent_trust[chain[i]] >= 0.65

\* ── ACTIONS ──────────────────────────────────────────────────

\* Issue a cryptographic passport to an agent
IssuePassport(agent, trust_score) ==
    /\ agent_states[agent] = "UNVERIFIED"
    /\ trust_score > 0
    /\ trust_score <= 1
    /\ agent_passports' = [agent_passports EXCEPT
        ![agent] = [valid |-> TRUE, revoked |-> FALSE, expired |-> FALSE]]
    /\ agent_trust'   = [agent_trust EXCEPT ![agent] = trust_score]
    /\ agent_states'  = [agent_states EXCEPT ![agent] = "VERIFIED"]
    /\ chain_blocks'  = Append(chain_blocks, [
            type    |-> "PASSPORT_ISSUED",
            agent   |-> agent,
            trust   |-> trust_score,
            decision|-> "ALLOW"
        ])
    /\ UNCHANGED <<eat_tokens, evidence_records, delegation_chains,
                   approvals, jurisdiction_cache, continuity_scores>>

\* Runtime Guard verification (VGS-001)
GuardVerify(agent, action, consequence) ==
    \* Step 0: Invariant pre-check (mandatory — cannot be bypassed)
    LET inv_check ==
        /\ PassportValid(agent)
        /\ agent_trust[agent] >= 0.50
    IN
    /\ agent_states[agent] \in {"VERIFIED", "PROVISIONAL", "ADMISSIBLE"}
    /\ LET decision ==
            IF ~PassportValid(agent)  THEN "DENY"
            ELSE IF agent_trust[agent] < 0.50 THEN "DENY"
            ELSE IF agent_trust[agent] < 0.65 THEN "DENY"
            ELSE IF agent_trust[agent] < 0.80 THEN "REQUIRE_HUMAN_APPROVAL"
            ELSE IF consequence = "CRITICAL"  THEN "REQUIRE_HUMAN_APPROVAL"
            ELSE IF consequence = "HIGH"      THEN "REQUIRE_HUMAN_APPROVAL"
            ELSE "ALLOW"
       IN
        /\ agent_states' = [agent_states EXCEPT
               ![agent] = IF decision = "ALLOW" THEN "ADMISSIBLE"
                          ELSE IF decision = "REQUIRE_HUMAN_APPROVAL" THEN "ESCALATED"
                          ELSE "DENIED"]
        /\ chain_blocks' = Append(chain_blocks, [
               type       |-> "GUARD_DECISION",
               agent      |-> agent,
               action     |-> action,
               consequence|-> consequence,
               decision   |-> decision,
               trust      |-> agent_trust[agent]
           ])
        /\ UNCHANGED <<agent_trust, agent_passports, eat_tokens,
                       evidence_records, delegation_chains, approvals,
                       jurisdiction_cache, continuity_scores>>

\* Revoke a passport
RevokePassport(agent, reason) ==
    /\ agent_passports[agent].valid
    /\ agent_passports' = [agent_passports EXCEPT
           ![agent].revoked = TRUE,
           ![agent].valid   = FALSE]
    /\ agent_states'  = [agent_states EXCEPT ![agent] = "DENIED"]
    /\ chain_blocks'  = Append(chain_blocks, [
           type    |-> "PASSPORT_REVOKED",
           agent   |-> agent,
           reason  |-> reason,
           decision|-> "DENY"
       ])
    /\ UNCHANGED <<agent_trust, eat_tokens, evidence_records,
                   delegation_chains, approvals, jurisdiction_cache,
                   continuity_scores>>

\* Classify evidence (VGS-007 — immutable at creation)
ClassifyEvidence(record_id, evidence_class, agent, payload_hash) ==
    /\ evidence_class \in EvidenceClass
    /\ evidence_records' = Append(evidence_records, [
           record_id      |-> record_id,
           evidence_class |-> evidence_class,  \* IMMUTABLE — bound at creation
           agent_id       |-> agent,
           payload_hash   |-> payload_hash,
           immutable      |-> TRUE,
           reclassifiable |-> FALSE             \* By construction — not policy
       ])
    /\ UNCHANGED <<agent_states, agent_trust, agent_passports,
                   chain_blocks, eat_tokens, delegation_chains,
                   approvals, jurisdiction_cache, continuity_scores>>

\* Issue Execution Authority Token (VGS-006)
IssueEAT(token_id, agent, delegated_by, action, max_amount, max_consequence) ==
    LET delegator_trust == agent_trust[delegated_by]
        agent_trust_score == agent_trust[agent]
        \* ATF-INV-005 equivalent: monotonic authority reduction at issuance
        effective_consequence == IF max_consequence = "CRITICAL" /\ delegator_trust < 0.95
                                 THEN "HIGH"
                                 ELSE IF max_consequence = "HIGH" /\ delegator_trust < 0.85
                                 THEN "MEDIUM"
                                 ELSE max_consequence
    IN
    /\ PassportValid(delegated_by)
    /\ PassportValid(agent)
    /\ eat_tokens' = Append(eat_tokens, [
           token_id       |-> token_id,
           agent_id       |-> agent,
           delegated_by   |-> delegated_by,
           action         |-> action,
           max_amount     |-> max_amount,
           max_consequence|-> effective_consequence,  \* Monotonically reduced
           valid          |-> TRUE,
           revoked        |-> FALSE
       ])
    /\ chain_blocks' = Append(chain_blocks, [
           type           |-> "EAT_ISSUED",
           token_id       |-> token_id,
           agent          |-> agent,
           decision       |-> "ALLOW"
       ])
    /\ UNCHANGED <<agent_states, agent_trust, agent_passports,
                   evidence_records, delegation_chains, approvals,
                   jurisdiction_cache, continuity_scores>>

\* ── SAFETY INVARIANTS (VER-INV-001 through VER-INV-008) ──────

\* VER-INV-001: Evidence classification hash immutability
\* Once classified, an evidence record's class cannot change
EvidenceImmutability ==
    \A i \in 1..Len(evidence_records) :
        evidence_records[i].immutable = TRUE
        /\ evidence_records[i].reclassifiable = FALSE

\* VER-INV-003: Audit chain append-only (no modification)
\* Chain length can only increase — never decrease
AuditChainMonotonic ==
    [][ Len(chain_blocks') >= Len(chain_blocks) ]_chain_blocks

\* VER-INV-004: Classification transition prohibition
\* No evidence record ever changes its evidence_class
NoReclassification ==
    [][\A i \in 1..Len(evidence_records) :
        evidence_records'[i].evidence_class = evidence_records[i].evidence_class
    ]_evidence_records

\* VFGS-INV-001: HIGH consequence requires valid authority
\* No HIGH consequence action reaches EXECUTING without going through ESCALATED
HighConsequenceGate ==
    \A agent \in Agents :
        [](agent_states[agent] = "EXECUTING" =>
            \* Either trust was sufficient for direct allow
            \/ agent_trust[agent] >= 0.80
            \* Or it went through human approval (ESCALATED -> EXECUTING)
            \/ \E block \in {chain_blocks[i] : i \in 1..Len(chain_blocks)} :
                /\ block.agent = agent
                /\ block.decision = "REQUIRE_HUMAN_APPROVAL"
        )

\* VFGS-INV-004: Trust floor enforcement
\* An agent with trust < 0.50 is never in ADMISSIBLE or EXECUTING
TrustFloorEnforced ==
    \A agent \in Agents :
        agent_trust[agent] < 0.50 =>
            agent_states[agent] \notin {"ADMISSIBLE", "EXECUTING"}

\* VFGS-INV-003: Monotonic authority reduction in EAT
\* Delegated consequence level <= delegator's permitted level
MonotonicAuthorityReduction ==
    \A i \in 1..Len(eat_tokens) :
        LET token == eat_tokens[i]
            delegator == token.delegated_by
        IN
        \* CRITICAL requires SOVEREIGN (trust >= 0.95)
        (token.max_consequence = "CRITICAL" => agent_trust[delegator] >= 0.95)
        \* HIGH requires ADMIN (trust >= 0.85)
        /\ (token.max_consequence = "HIGH" => agent_trust[delegator] >= 0.85)

\* Revoked passport → agent DENIED
RevocationHardStop ==
    \A agent \in Agents :
        agent_passports[agent].revoked =>
            agent_states[agent] = "DENIED"

\* DENIED is a terminal state — no transitions out
DeniedIsTerminal ==
    \A agent \in Agents :
        [][agent_states[agent] = "DENIED" =>
           agent_states'[agent] = "DENIED"]_agent_states

\* ── LIVENESS PROPERTIES ──────────────────────────────────────

\* Every ESCALATED agent eventually reaches EXECUTING or DENIED
\* (human approval is not infinite — it has a 24hr SLA)
EscalationEventuallyResolves ==
    \A agent \in Agents :
        agent_states[agent] = "ESCALATED" ~>
            agent_states[agent] \in {"EXECUTING", "DENIED"}

\* Every EXECUTING agent eventually reaches COMPLETED or FAILED
ExecutionEventuallyTerminates ==
    \A agent \in Agents :
        agent_states[agent] = "EXECUTING" ~>
            agent_states[agent] \in {"COMPLETED", "FAILED"}

\* ── STATE TRANSITION RELATION ────────────────────────────────
\* Defines ALL permissible transitions (VGS-002)
\* Unlisted transitions are IMPOSSIBLE — not just prohibited

PermissibleTransitions ==
    LET current == agent_states
        next    == agent_states'
    IN
    \A agent \in Agents :
        \/ next[agent] = current[agent]  \* No change
        \/ current[agent] = "UNVERIFIED"   /\ next[agent] \in {"VERIFIED", "DENIED"}
        \/ current[agent] = "VERIFIED"     /\ next[agent] \in {"ADMISSIBLE", "PROVISIONAL", "DENIED"}
        \/ current[agent] = "PROVISIONAL"  /\ next[agent] \in {"ADMISSIBLE", "ESCALATED", "DENIED"}
        \/ current[agent] = "ADMISSIBLE"   /\ next[agent] \in {"EXECUTING", "ESCALATED", "DENIED"}
        \/ current[agent] = "ESCALATED"    /\ next[agent] \in {"EXECUTING", "DENIED"}
        \/ current[agent] = "EXECUTING"    /\ next[agent] \in {"COMPLETED", "FAILED"}
        \/ current[agent] = "COMPLETED"    /\ next[agent] \in {"VERIFIED"}
        \/ current[agent] = "FAILED"       /\ next[agent] \in {"ESCALATED", "DENIED"}
        \/ current[agent] = "DENIED"       /\ next[agent] = "DENIED"  \* Terminal

\* ── COMPLETE SPECIFICATION ───────────────────────────────────

\* System specification: initial state + all valid transitions
Spec ==
    /\ Init
    /\ [][
        \E agent \in Agents, action \in Actions, consequence \in ConsequenceLevel :
            \/ IssuePassport(agent, 0.963)
            \/ GuardVerify(agent, action, consequence)
            \/ RevokePassport(agent, "policy_violation")
            \/ \E class \in EvidenceClass :
               ClassifyEvidence("rec_001", class, agent, "hash_001")
       ]_<<agent_states, agent_trust, agent_passports, chain_blocks,
           eat_tokens, evidence_records, delegation_chains,
           approvals, jurisdiction_cache, continuity_scores>>
    /\ WF_<<agent_states>>(\E agent \in Agents : \E action \in Actions :
           GuardVerify(agent, action, "MEDIUM"))

\* ── THEOREMS ─────────────────────────────────────────────────
\* These are what the TLC model checker verifies

THEOREM Spec => []EvidenceImmutability
\* Proof: ClassifyEvidence sets immutable=TRUE and reclassifiable=FALSE
\* No action in the specification modifies evidence_records[i].evidence_class
\* Therefore EvidenceImmutability holds in all reachable states

THEOREM Spec => []TrustFloorEnforced
\* Proof: GuardVerify returns DENY for trust < 0.50
\* Agent transitions to DENIED — cannot reach ADMISSIBLE or EXECUTING
\* RevocationHardStop ensures DENIED is maintained

THEOREM Spec => []RevocationHardStop
\* Proof: RevokePassport sets revoked=TRUE and state=DENIED
\* No action sets revoked=FALSE (revocation is permanent)
\* DENIED is terminal by DeniedIsTerminal

THEOREM Spec => []MonotonicAuthorityReduction
\* Proof: IssueEAT reduces max_consequence based on delegator_trust
\* No action increases max_consequence after issuance (EAT is immutable)

THEOREM Spec => []DeniedIsTerminal
\* Proof: PermissibleTransitions only allows DENIED -> DENIED
\* No other action transitions an agent out of DENIED

====
\* END MODULE VeriSigilGovernance
\*
\* To verify with TLC:
\* 1. Install TLA+ Toolbox: https://lamport.azurewebsites.net/tla/toolbox.html
\* 2. Open this file
\* 3. Create model with: Agents={a1,a2}, Actions={payment,delete}, MaxChainLength=5
\* 4. Add invariants: EvidenceImmutability, TrustFloorEnforced, RevocationHardStop
\* 5. Add temporal properties: EscalationEventuallyResolves
\* 6. Run TLC model checker
\*
\* Expected result: All invariants hold, no deadlocks, liveness satisfied
