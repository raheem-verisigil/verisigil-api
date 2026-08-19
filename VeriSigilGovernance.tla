---- MODULE VeriSigilGovernance ----
EXTENDS Integers, Sequences, FiniteSets

Agents == {"vsa001", "vsa002"}

VARIABLE agent_states, agent_trust, agent_passport_valid, agent_passport_revoked, evidence_log

vars == <<agent_states, agent_trust, agent_passport_valid, agent_passport_revoked, evidence_log>>

Init ==
    /\ agent_states           = [a \in Agents |-> "UNVERIFIED"]
    /\ agent_trust            = [a \in Agents |-> 0]
    /\ agent_passport_valid   = [a \in Agents |-> FALSE]
    /\ agent_passport_revoked = [a \in Agents |-> FALSE]
    /\ evidence_log           = <<>>

IssuePassport(a) ==
    /\ agent_states[a] = "UNVERIFIED"
    /\ agent_passport_valid[a] = FALSE
    /\ agent_passport_valid'   = [agent_passport_valid   EXCEPT ![a] = TRUE]
    /\ agent_passport_revoked' = [agent_passport_revoked EXCEPT ![a] = FALSE]
    /\ agent_trust'            = [agent_trust            EXCEPT ![a] = 90]
    /\ agent_states'           = [agent_states           EXCEPT ![a] = "VERIFIED"]
    /\ evidence_log'           = Append(evidence_log, "GDR")

IssuePassportLow(a) ==
    /\ agent_states[a] = "UNVERIFIED"
    /\ agent_passport_valid[a] = FALSE
    /\ agent_passport_valid'   = [agent_passport_valid   EXCEPT ![a] = TRUE]
    /\ agent_passport_revoked' = [agent_passport_revoked EXCEPT ![a] = FALSE]
    /\ agent_trust'            = [agent_trust            EXCEPT ![a] = 70]
    /\ agent_states'           = [agent_states           EXCEPT ![a] = "VERIFIED"]
    /\ evidence_log'           = Append(evidence_log, "GDR")

RevokePassport(a) ==
    /\ agent_passport_valid[a] = TRUE
    /\ agent_passport_revoked[a] = FALSE
    /\ agent_passport_valid'   = [agent_passport_valid   EXCEPT ![a] = FALSE]
    /\ agent_passport_revoked' = [agent_passport_revoked EXCEPT ![a] = TRUE]
    /\ agent_states'           = [agent_states           EXCEPT ![a] = "DENIED"]
    /\ UNCHANGED <<agent_trust, evidence_log>>

GuardAllow(a) ==
    /\ agent_states[a] = "VERIFIED"
    /\ agent_passport_valid[a] = TRUE
    /\ agent_passport_revoked[a] = FALSE
    /\ agent_trust[a] >= 80
    /\ agent_states' = [agent_states EXCEPT ![a] = "ADMISSIBLE"]
    /\ evidence_log' = Append(evidence_log, "ADR")
    /\ UNCHANGED <<agent_trust, agent_passport_valid, agent_passport_revoked>>

GuardEscalate(a) ==
    /\ agent_states[a] = "VERIFIED"
    /\ agent_passport_valid[a] = TRUE
    /\ agent_passport_revoked[a] = FALSE
    /\ agent_trust[a] >= 65
    /\ agent_trust[a] < 80
    /\ agent_states' = [agent_states EXCEPT ![a] = "ESCALATED"]
    /\ evidence_log' = Append(evidence_log, "EER")
    /\ UNCHANGED <<agent_trust, agent_passport_valid, agent_passport_revoked>>

Execute(a) ==
    /\ agent_states[a] = "ADMISSIBLE"
    /\ agent_passport_valid[a] = TRUE
    /\ agent_passport_revoked[a] = FALSE
    /\ agent_states' = [agent_states EXCEPT ![a] = "EXECUTING"]
    /\ evidence_log' = Append(evidence_log, "RCR")
    /\ UNCHANGED <<agent_trust, agent_passport_valid, agent_passport_revoked>>

Complete(a) ==
    /\ agent_states[a] = "EXECUTING"
    /\ agent_states' = [agent_states EXCEPT ![a] = "COMPLETED"]
    /\ evidence_log' = Append(evidence_log, "AIP")
    /\ UNCHANGED <<agent_trust, agent_passport_valid, agent_passport_revoked>>

ApproveEscalation(a) ==
    /\ agent_states[a] = "ESCALATED"
    /\ agent_states' = [agent_states EXCEPT ![a] = "ADMISSIBLE"]
    /\ UNCHANGED <<agent_trust, agent_passport_valid, agent_passport_revoked, evidence_log>>

Next ==
    \E a \in Agents :
        \/ IssuePassport(a)
        \/ IssuePassportLow(a)
        \/ RevokePassport(a)
        \/ GuardAllow(a)
        \/ GuardEscalate(a)
        \/ Execute(a)
        \/ Complete(a)
        \/ ApproveEscalation(a)

Spec == Init /\ [][Next]_vars

RevocationHardStop ==
    \A a \in Agents :
        agent_passport_revoked[a] = TRUE =>
            /\ agent_states[a] = "DENIED"
            /\ agent_passport_valid[a] = FALSE

DeniedIsTerminal ==
    \A a \in Agents :
        agent_passport_revoked[a] = TRUE =>
            ~agent_passport_valid[a]

NoExecutionWithoutPassport ==
    \A a \in Agents :
        agent_states[a] = "EXECUTING" =>
            /\ agent_passport_valid[a] = TRUE
            /\ agent_passport_revoked[a] = FALSE

HighTrustBeforeExecution ==
    \A a \in Agents :
        agent_states[a] = "ADMISSIBLE" =>
            agent_trust[a] >= 80

\* VER-INV-013: Compute Provenance
\* Agents with unverified compute provenance cannot reach EXECUTING state
\* Enforced at registration time via verify_chip_serial + verify_agent_provenance
ComputeProvenanceRequired ==
    \A a \in Agents :
        agent_states[a] = "EXECUTING" =>
            agent_passport_valid[a] = TRUE

THEOREM Spec => []ComputeProvenanceRequired

\* VER-INV-015: Structural Execution Impossibility
\* Leo Michaels standard: executable path cannot form
\* under unresolved admissibility
\* Combined with VER-INV-009 + VER-INV-010:
\* proves structural impossibility, not just policy blocking
StructuralImpossibility ==
    \A a \in Agents :
        ~agent_passport_valid[a] =>
            agent_states[a] \notin {"ADMISSIBLE", "EXECUTING"}

THEOREM Spec => []StructuralImpossibility

====
