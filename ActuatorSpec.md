# ActuatorSpec.tla — VeriSigil Formal Verification

**Module:** ActuatorSpec  
**Tool:** TLA+ / TLC Model Checker  
**Invariants:** NoBypass, NoReplay  
**Status:** Machine-checkable — run with TLC against a finite model of Nonces and Actions

---

## What this proves

Across every reachable state, under every possible interleaving of issuing, expiring, letting state drift, and executing — two invariants must hold:

1. **NoBypass** — every executed action must correspond to a token that was genuinely issued for that exact (nonce, action) pair. No action can appear in `executed` that no token was ever issued for.

2. **NoReplay** — no nonce may appear in more than one execution event. The replay guard holds across every reachable state and every interleaving, not just the cases a human tester happened to think of.

## Honest gap (spec §8.3)

This is a MODEL of the actuator's control logic, not the Python implementation itself. Proving the model correct does not automatically prove the deployed code matches the model. That gap requires either (a) generating the actuator's enforcement logic directly from the verified spec, or (b) an independent code audit. It is real and not closed here.

## Why SEQUENCE not SET for `executed`

`executed` is modeled as a SEQUENCE deliberately. A set would silently collapse two identical execution events into one element, hiding a real replay. A sequence records every execution attempt as its own event, so a replay is actually observable to the checker.

---

```tla
---- MODULE ActuatorSpec ----
(*
Formal model of the WireTransferActuator's state machine (spec §8).

This models the abstract lifecycle of an Authorization Object and asks:
across every reachable state, under every possible interleaving of
issuing, expiring, letting state drift, and executing — does an executed
action always correspond to a token that was genuinely issued for it, and
is each token ever consumed more than once?

`executed` is modeled as a SEQUENCE, not a set, deliberately: a set would
silently collapse two identical execution events into one element,
hiding a real replay. A sequence records every execution attempt as its
own event, so a replay is actually observable to the checker.

This is a MODEL of the actuator's control logic, not the Python
implementation itself. Spec §8.3 is explicit about the gap this leaves:
proving the model correct does not automatically prove the deployed code
matches the model. That gap is real and is not closed here.
*)

EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS Nonces, Actions

VARIABLES issued, executed

vars == <<issued, executed>>

TokenRecord == [nonce: Nonces, action: Actions, expired: BOOLEAN, fresh: BOOLEAN]
ExecEvent == [nonce: Nonces, action: Actions]

TypeOK ==
    /\ issued \subseteq TokenRecord
    /\ executed \in Seq(ExecEvent)

Init ==
    /\ issued = {}
    /\ executed = <<>>

ConsumedNonces == { executed[i].nonce : i \in DOMAIN executed }

(* Governance issues a fresh, unexpired token for (n, a). Cannot reissue a
   nonce that's already outstanding or already been consumed. *)
IssueToken(n, a) ==
    /\ n \notin { t.nonce : t \in issued }
    /\ n \notin ConsumedNonces
    /\ issued' = issued \cup { [nonce |-> n, action |-> a, expired |-> FALSE, fresh |-> TRUE] }
    /\ UNCHANGED executed

(* Models time passing: an outstanding token can expire. *)
ExpireToken(n) ==
    /\ \E t \in issued : t.nonce = n
    /\ issued' = { IF t.nonce = n THEN [t EXCEPT !.expired = TRUE] ELSE t : t \in issued }
    /\ UNCHANGED executed

(* Models the world state changing after issuance, before use. *)
DriftToken(n) ==
    /\ \E t \in issued : t.nonce = n
    /\ issued' = { IF t.nonce = n THEN [t EXCEPT !.fresh = FALSE] ELSE t : t \in issued }
    /\ UNCHANGED executed

(* THE ENFORCEMENT GUARD — this is the actual property under test. An
   action can only be appended to `executed` if a matching, unexpired,
   state-fresh token exists AND its nonce has not already been consumed. *)
ExecuteAction(n, a) ==
    /\ \E t \in issued :
        /\ t.nonce = n
        /\ t.action = a
        /\ t.expired = FALSE
        /\ t.fresh = TRUE
    /\ n \notin ConsumedNonces
    /\ executed' = Append(executed, [nonce |-> n, action |-> a])
    /\ UNCHANGED issued

Next ==
    \/ \E n \in Nonces, a \in Actions : IssueToken(n, a)
    \/ \E n \in Nonces : ExpireToken(n)
    \/ \E n \in Nonces : DriftToken(n)
    \/ \E n \in Nonces, a \in Actions : ExecuteAction(n, a)

Spec == Init /\ [][Next]_vars

(* THE INVARIANT (spec §8.2's NoBypass, restated for this model): every
   executed event must correspond to SOME token that was genuinely issued
   for that exact (nonce, action) pair. No action can appear in `executed`
   that no token was ever issued for. *)
NoBypass ==
    \A i \in DOMAIN executed :
        \E t \in issued :
            /\ t.nonce = executed[i].nonce
            /\ t.action = executed[i].action

(* No nonce may appear in more than one execution event — the replay
   guard must hold across every reachable state and every interleaving,
   not just the cases a human tester happened to think of. *)
NoReplay ==
    \A i, j \in DOMAIN executed :
        (executed[i].nonce = executed[j].nonce) => (i = j)

====
```

---

## How to run with TLC

1. Install the [TLA+ Toolbox](https://github.com/tlaplus/tlaplus/releases) or use [tla2tools.jar](https://github.com/tlaplus/tlaplus/releases)
2. Create a model with finite instantiations:
   - `Nonces` = `{"n1", "n2", "n3"}`
   - `Actions` = `{"transfer", "delete"}`
3. Set invariants: `NoBypass`, `NoReplay`, `TypeOK`
4. Run TLC — it exhaustively checks all reachable states

If TLC returns with no violations, `NoBypass` and `NoReplay` hold across every possible interleaving of issue, expire, drift, and execute operations.

---

*Published by VeriSigil AI — raheem@verisigilai.com*  
*Part of the Provable Execution Integrity Layer (VGS-PEI)*
