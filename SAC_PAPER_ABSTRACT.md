# State-to-Action Coherence in Memory-Enabled AI Agents:
## A Framework, Reference Implementation, and Benchmark

**Working paper — not for public release until VeriSigil P1-A closes**  
**Architecture freeze in effect: this is research/writing, not engineering**

---

## Abstract

Memory-enabled AI agents increasingly operate in environments where previously
valid state — authorization records, retrieved evidence, policy snapshots, and
authority grants — can become invalid between the moment a decision is made and
the moment a consequential action is executed. We call the failure mode that
results from acting on invalidated state *state-action incoherence*.

Existing approaches to AI safety and governance address action authorization at
decision time. They do not systematically address whether the state and evidence
that justified a decision remain valid, applicable, authorized, and sufficient
*at execution time* — particularly when execution is delayed, when authority
can be revoked after a decision is made, or when parameters drift between
approval and consequence.

We define *State-to-Action Coherence* (SAC) as the property that holds when:
(1) the state used to justify a proposed action is still valid at the moment of
execution, (2) the authority under which the action is proposed has not been
revoked, expired, or exceeded, (3) the exact parameters of the proposed action
match those that were authorized, and (4) the evidence supporting the action
has not been invalidated by temporal, policy, authority, dependency, or scope
changes.

We identify five primary *SAC-invalidation classes*:

- **Temporal invalidation**: authorization or evidence has expired
- **Policy invalidation**: governing policy has changed since authorization
- **Authority invalidation**: the granting authority has been revoked or transferred
- **Dependency invalidation**: a dependency the action relies on has changed
- **Scope invalidation**: the proposed action exceeds the scope of the original authorization

We present a reference implementation — the VeriSigil Consequence Boundary —
that operates as an independent enforcement layer downstream of state-validity
assessment. The reference implementation enforces these properties at the
consequence boundary through a STILL gate (re-establishes current authority
from an authoritative store, independent of agent-supplied state), a parameter-
binding commitment (cryptographically locks the exact authorized action before
execution), and a fail-closed actuator that refuses execution when the required
proposition cannot be established.

We introduce *SAC-Bench*, a benchmark suite for evaluating state-to-action
coherence enforcement. SAC-Bench defines controlled test cases across all five
invalidation classes, including explicit non-invalidation controls, and measures
detection rate, enforcement escape rate, evidence completeness, and false-
positive rate. Unlike existing AI safety benchmarks, SAC-Bench specifically
targets the execution-time coherence gap rather than decision-time authorization.

Under the tested conditions with the reference implementation, all five
invalidation classes were correctly detected and enforcement was applied before
the consequence boundary was crossed. Fail-closed behavior was confirmed: when
current authority could not be established, the system refused rather than
defaulting to authorization. An independent external engineer reproduced the
core enforcement behavior using only a published verification procedure and a
public key, without access to the implementation.

We do not claim that SAC solves AI safety, prevents all unauthorized actions,
or replaces regulatory frameworks. We claim that the identified failure mode is
real, measurable, and addressable through a specific enforcement architecture
whose behavior can be independently tested.

---

## Key Contributions

1. **Definition**: A precise definition of state-to-action coherence and its
   five primary invalidation classes

2. **Architecture**: The Governance Physiology explanatory model — a biological
   metaphor for how consequential AI actions move through structured evaluation
   stages before reaching an external actuator

3. **Reference implementation**: VeriSigil as an independently testable
   consequence boundary that enforces SAC properties at execution time

4. **Benchmark**: SAC-Bench — the first published benchmark specifically
   designed to evaluate state-to-action coherence enforcement

5. **Evidence discipline**: A methodology for separating "state validity" from
   "execution authority" and producing portable cryptographic evidence of each
   determination

---

## What This Paper Does Not Claim

- We did not invent memory coherence or action authorization
- We did not invent the concept of stale state
- Biological terminology is an explanatory metaphor, not a proprietary invention
- The reference implementation is not production-certified or regulatory-compliant
- SAC-Bench results are bounded by the tested conditions and the single-instance
  reference deployment
- State-to-action coherence detection does not guarantee that authorized actions
  are ethically correct

---

## Related Work

The state-validity problem has appeared in multiple adjacent research tracks:
stale-plan execution in robotics (Ziebart et al.), authorization laundering in
agent systems (recent 2025-2026 work), always-on agent monitoring (emerging),
and context-window integrity (nascent). Our contribution differs in three ways:
we treat SAC as a first-class named property, we focus specifically on the
execution-time coherence gap rather than decision-time, and we provide an
independently testable reference implementation with a specific benchmark.

---

*PRODUCTION_CLAIM_ALLOWED: False — research paper direction only*  
*Architecture freeze in effect — no new engineering from this paper*  
*VeriSigil P1-A (Alkama Run 8) must close before any SAC engineering begins*
