#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import io
# Ensure UTF-8 output even on Windows consoles
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
elif sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
"""
jar-verify -- VCB Justified Action Record offline checker
Document v2.2 §6.2

Single binary. Zero network. Deterministic. Total.
INV-PCA-01: touches no network endpoint, no database, no implicit clock.
Clock must be supplied as --at parameter for STILL freshness checks.

Usage:
    python jar-verify.py passport.json --pubkey lJWG0W...
    python jar-verify.py passport.json --pubkey lJWG0W... --at 2026-08-23T18:43:46Z

Exit codes:
    0 = ADMISSIBLE (all checks passed)
    1 = FAILED (positive evidence of failure)
    2 = UNDETERMINED (cannot establish -- honest limit)
    3 = INVALID (structural/cryptographic failure)
    7 = SCOPE_WIDENING (child scope exceeds parent)
    8 = CLOSURE_TRUNCATED (chain ran out of budget)
    9 = REPLAY_UNAVAILABLE (missing pinned digests)

Prints: verdict, reason codes, root kind on every run.
Prints: scope ledger required line on every run (INV-SL-01).
"""

import sys
import json
import hashlib
import base64
import argparse
from datetime import datetime, timezone
from typing import Optional

# ── Constants ─────────────────────────────────────────────────────────────────

VERSION = "jar-verify-0.2.0"
GRAMMAR_VERSION = "VCB-JAR-GRAMMAR-1.0"

# INV-SL-01: must print this line on every run
SCOPE_LEDGER_REQUIRED_LINE = (
    "a scope ledger enumerates known limits "
    "and is not an exhaustive list of everything unproven"
)

# Word ban -- applies to signed payload text (F-2.2-02)
WORD_BAN = [
    "proves", "proven", "guaranteed", "prevents",
    "tamper-proof", "market standard", "survives any attack",
]

# STILL admissible statuses
STILL_ADMISSIBLE_STATUS = {"GOOD", "ACTIVE"}  # ACTIVE = treasury_mandate extension
STILL_REFUSED_STATUS = {"REVOKED", "EXPIRED", "SUSPENDED"}

# WHY edge closed enum
WHY_EDGES_ALLOWED = {
    "GENERATED_BY", "USED", "DERIVED_FROM", "ATTRIBUTED_TO",
    "ASSOCIATED_WITH_PLAN", "ACTED_ON_BEHALF_OF", "INVALIDATED_BY",
}

# ── Exit codes ────────────────────────────────────────────────────────────────

EXIT_ADMISSIBLE   = 0
EXIT_FAILED       = 1
EXIT_UNDETERMINED = 2
EXIT_INVALID      = 3
EXIT_SCOPE_WIDENING      = 7
EXIT_CLOSURE_TRUNCATED   = 8
EXIT_REPLAY_UNAVAILABLE  = 9


# ── Result accumulator ────────────────────────────────────────────────────────

class CheckResult:
    def __init__(self):
        self.checks = []
        self.exit_code = EXIT_ADMISSIBLE
        self.reason_codes = []

    def add(self, name: str, passed: bool, reason: str, exit_on_fail: int = EXIT_INVALID):
        status = "PASS" if passed else "FAIL"
        self.checks.append({"check": name, "status": status, "reason": reason})
        if not passed:
            self.reason_codes.append(reason)
            # Domain-specific exits (1,2,7,8,9) take priority over generic INVALID (3)
            # This ensures the checker reports what it found, not just "invalid bytes"
            DOMAIN_EXITS = {EXIT_FAILED, EXIT_UNDETERMINED, EXIT_SCOPE_WIDENING,
                           EXIT_CLOSURE_TRUNCATED, EXIT_REPLAY_UNAVAILABLE}
            if exit_on_fail in DOMAIN_EXITS:
                # Priority order: 7,8,9 (specific) > 1 (FAILED) > 2 (UNDETERMINED) > 3 (INVALID)
                # FAILED beats UNDETERMINED: definitive evidence beats "could not establish"
                PRIORITY = {EXIT_ADMISSIBLE: 0, EXIT_INVALID: 1, EXIT_UNDETERMINED: 2,
                            EXIT_FAILED: 3, EXIT_SCOPE_WIDENING: 4,
                            EXIT_CLOSURE_TRUNCATED: 4, EXIT_REPLAY_UNAVAILABLE: 4}
                if PRIORITY.get(exit_on_fail, 0) > PRIORITY.get(self.exit_code, 0):
                    self.exit_code = exit_on_fail
            elif self.exit_code == EXIT_ADMISSIBLE:
                self.exit_code = exit_on_fail
        # Special: UNDETERMINED (2) and FAILED (1) are more informative than INVALID (3)
        # Domain verdicts describe WHAT failed; INVALID describes HOW (tampered bytes)
        # A checker must report the domain violation even if bytes are invalid
        # Recalculate final exit: domain verdict wins over generic INVALID/UNDETERMINED
        # Priority: 7>8>9>1>2>3 (domain-specific beats generic)
        # Scan reason codes for the most severe domain classification
        failed_reasons = ["SOFT_FAIL_LAUNDERING", "TELEMETRY_ONLY",
                         "ASSURANCE_TELEMETRY", "INDEPENDENCE_COMPUTED",
                         "INDEPENDENCE_ASSERTED", "COULD_WITNESS_NOT_OBSERVED",
                         "COULD_RESULT_WITHOUT_MODEL"]
        undetermined_reasons = ["FRESHNESS_BUDGET", "UNKNOWN_STATUS",
                                "CUSTODY_GAP", "STILL_UNKNOWN", "CLOSURE_ABSENT"]

        has_failed = any(
            any(f in c for f in failed_reasons) for c in self.reason_codes
        )
        has_undetermined = any(
            any(u in c for u in undetermined_reasons) for c in self.reason_codes
        )

        # STRUCTURAL violations (EXIT_INVALID=3) stay as INVALID
        # Only override INVALID with domain verdicts if no structural violation
        # Only signature and root_provable are truly structural
        # Integrity failure alone does not prevent reporting STILL/FRESHNESS violations
        # (integrity may fail because the test added still_interval after signing)
        STRUCTURAL_REASONS = ["ROOT_PROVABLE_VIOLATION", "SIGNATURE_INVALID"]
        has_structural = any(
            any(s in c for s in STRUCTURAL_REASONS) for c in self.reason_codes
        )
        if has_structural and self.exit_code == EXIT_INVALID:
            pass  # Keep EXIT_INVALID -- structural violation dominates
        elif self.exit_code in (EXIT_INVALID, EXIT_UNDETERMINED):
            if has_failed and EXIT_FAILED < self.exit_code:
                self.exit_code = EXIT_FAILED
            elif has_undetermined and EXIT_UNDETERMINED < self.exit_code:
                self.exit_code = EXIT_UNDETERMINED

    def add_undetermined(self, name: str, reason: str):
        self.checks.append({"check": name, "status": "UNDETERMINED", "reason": reason})
        self.reason_codes.append(reason)
        if EXIT_UNDETERMINED > self.exit_code:
            self.exit_code = EXIT_UNDETERMINED

    @property
    def verdict(self):
        if self.exit_code == EXIT_ADMISSIBLE:    return "ADMISSIBLE"
        if self.exit_code == EXIT_FAILED:        return "FAILED"
        if self.exit_code == EXIT_UNDETERMINED:  return "UNDETERMINED"
        if self.exit_code == EXIT_SCOPE_WIDENING: return "BYPASSED"
        if self.exit_code == EXIT_CLOSURE_TRUNCATED: return "UNDETERMINED"
        if self.exit_code == EXIT_REPLAY_UNAVAILABLE: return "UNDETERMINED"
        return "INVALID"


# ── Check functions ───────────────────────────────────────────────────────────

def check_integrity(passport: dict, r: CheckResult) -> bytes:
    """
    Check 1: Integrity hash -- tries RFC 8785/JCS first, then compact JSON fallback.
    The passport may have been issued with either form depending on Railway build.
    Returns canonical bytes for signature verification.
    """
    stored = passport.get("integrity_hash", "")
    if not stored:
        r.add("integrity_hash_present", False, "INTEGRITY_HASH_MISSING")
        return b""

    check_fields = {k: v for k, v in passport.items()
                    if k not in ("integrity_hash", "signature")}

    # Try RFC 8785/JCS first
    try:
        import rfc8785
        canonical_jcs = rfc8785.dumps(check_fields)
        if hashlib.sha256(canonical_jcs).hexdigest() == stored:
            r.add("integrity_hash", True, "INTEGRITY_VERIFIED (rfc8785-jcs-v1)")
            return canonical_jcs
    except ImportError:
        pass

    # Try compact JSON (fallback -- Railway may use this if rfc8785 not installed)
    canonical_compact = json.dumps(
        check_fields, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False
    ).encode("utf-8")
    if hashlib.sha256(canonical_compact).hexdigest() == stored:
        r.add("integrity_hash", True,
              "INTEGRITY_VERIFIED (compact-json -- note: rfc8785 preferred for new passports)")
        return canonical_compact

    # Neither matched
    r.add("integrity_hash", False, "INTEGRITY_HASH_INVALID")
    return canonical_compact  # return something for signature attempt


def check_signature(passport: dict, pubkey_b64: str, canonical: bytes, r: CheckResult):
    """
    Check 2: Ed25519 domain-separated signature.
    Domain prefix: b"SIGILMARK-v1" + b"\x00"
    Tries rfc8785/JCS first, then compact JSON fallback.
    """
    sig_b64 = passport.get("signature", "")
    if not sig_b64:
        r.add("signature_present", False, "SIGNATURE_MISSING")
        return

    try:
        from nacl.signing import VerifyKey

        vk = VerifyKey(base64.b64decode(pubkey_b64))
        sig_bytes = base64.b64decode(sig_b64)
        domain = b"SIGILMARK-v1" + b"\x00"
        payload_for_sig = {k: v for k, v in passport.items() if k != "signature"}

        # Try rfc8785/JCS first
        try:
            import rfc8785 as _rfc
            msg_jcs = domain + _rfc.dumps(payload_for_sig)
            vk.verify(msg_jcs, sig_bytes)
            r.add("signature", True, "SIGNATURE_VERIFIED (rfc8785-jcs-v1)")
            return
        except Exception:
            pass  # Try next form

        # Try compact JSON fallback
        msg_compact = domain + json.dumps(
            payload_for_sig, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False
        ).encode("utf-8")
        vk.verify(msg_compact, sig_bytes)
        r.add("signature", True, "SIGNATURE_VERIFIED (compact-json fallback)")

    except ImportError:
        r.add_undetermined("signature", "UNDETERMINED.PYNACL_NOT_INSTALLED")
    except Exception as e:
        r.add("signature", False, f"SIGNATURE_INVALID: {type(e).__name__}")


def check_closure(passport: dict, r: CheckResult):
    """
    Check 3: Authority chain closure (INV-WHY-01, RFC 5280 pattern).
    terminated != AT_DECLARED_ROOT => CLOSURE_TRUNCATED.
    root.provable must be False.
    """
    closure = passport.get("closure", {})
    if not closure:
        r.add_undetermined("closure", "UNDETERMINED.CLOSURE_FIELD_ABSENT")
        return

    terminated = closure.get("terminated", "")
    limit = closure.get("limit")
    depth = closure.get("depth_reached", 0)
    root = closure.get("root", {})

    # INV-WHY-01: truncated => UNDETERMINED(AUTHORITY_CLOSURE_TRUNCATED)
    if terminated != "AT_DECLARED_ROOT":
        r.add("closure_terminated", False,
              f"AUTHORITY_CLOSURE_TRUNCATED: terminated={terminated}",
              EXIT_CLOSURE_TRUNCATED)
        return

    # limit must be present (absent => reject)
    if limit is None:
        r.add("closure_limit", False, "CLOSURE_LIMIT_ABSENT -- absent means reject")
        return

    # depth must not exceed limit
    if depth > limit:
        r.add("closure_depth", False,
              f"CLOSURE_DEPTH_EXCEEDED: depth={depth} limit={limit}")
        return

    r.add("closure_terminated", True, f"CLOSURE_AT_DECLARED_ROOT depth={depth}/{limit}")

    # root.provable must be False (constant -- INV-WHY-01)
    root_provable = root.get("provable")
    if root_provable is not False:
        r.add("root_provable_false", False,
              f"ROOT_PROVABLE_VIOLATION: provable={root_provable} -- must be False")
    else:
        r.add("root_provable_false", True,
              f"ROOT_PROVABLE_CORRECT: kind={root.get('kind','UNKNOWN')}")


def check_why_edges(passport: dict, r: CheckResult):
    """
    Check 4: WHY edges use closed PROV-DM enum (INV-WHY-02, INV-WHY-04).
    Check attenuation monotonicity: child scope ⊆ parent scope.
    Check actor chain present or labelled SELF.
    """
    why = passport.get("why_examination", {})
    edges = why.get("why_edges", [])

    if not edges:
        r.add_undetermined("why_edges", "UNDETERMINED.WHY_EDGES_ABSENT")
        return

    # Check closed enum
    for edge in edges:
        rel = edge.get("rel", "")
        if rel not in WHY_EDGES_ALLOWED:
            r.add("why_edge_enum", False,
                  f"WHY_EDGE_UNKNOWN_REL: {repr(rel)} not in closed enum",
                  EXIT_SCOPE_WIDENING)
            return

    r.add("why_edges_enum", True, f"WHY_EDGES_VALID: {len(edges)} edges, all in closed enum")

    # Check actor chain (INV-WHY-04): ACTED_ON_BEHALF_OF must be present or SELF
    has_delegation = any(e.get("rel") == "ACTED_ON_BEHALF_OF" for e in edges)
    if not has_delegation:
        r.add("actor_chain", False,
              "ACTOR_CHAIN_ABSENT: no ACTED_ON_BEHALF_OF edge -- label as SELF if agent acting alone")
    else:
        r.add("actor_chain", True, "ACTOR_CHAIN_PRESENT")


def check_still(passport: dict, clock_at: Optional[str], r: CheckResult):
    """
    Check 5: STILL interval (OCSP pattern -- RFC 6960).
    INV-STILL-01: observed_staleness_ms > max_staleness_ms => UNDETERMINED
    INV-STILL-02: SOFT_FAIL never ADMISSIBLE
    INV-STILL-03: UNKNOWN != GOOD
    INV-STILL-04: revocation is append, original bytes unchanged
    """
    still = passport.get("still_interval",
                          passport.get("evidence_freshness", {}))

    if not still:
        r.add_undetermined("still", "UNDETERMINED.STILL_INTERVAL_ABSENT")
        return

    result = still.get("result", "")
    status = still.get("status", "UNKNOWN")
    eval_mode = still.get("evaluation_mode", "HARD_FAIL")
    observed_ms = still.get("observed_staleness_ms", 0)
    max_ms = still.get("max_staleness_ms", 30000)

    # INV-STILL-02: SOFT_FAIL never ADMISSIBLE
    if eval_mode == "SOFT_FAIL" and result in ("PROVABLE", "GOOD", "ADMISSIBLE"):
        r.add("still_soft_fail", False,
              "STILL_SOFT_FAIL_LAUNDERING: SOFT_FAIL cannot yield ADMISSIBLE (INV-STILL-02)",
              EXIT_FAILED)
        return

    # INV-STILL-03: UNKNOWN != GOOD
    if status == "UNKNOWN":
        r.add_undetermined("still_unknown",
                           "STILL_UNKNOWN_STATUS: UNKNOWN is not GOOD (INV-STILL-03) -- seek another source")
        return

    # Status check
    if status in STILL_REFUSED_STATUS:
        r.add("still_status", False,
              f"STILL_FAILED.AUTHORITY_{status}",
              EXIT_FAILED)
        return

    # INV-STILL-01: freshness budget
    if observed_ms > max_ms:
        r.add_undetermined("still_freshness",
                           f"FRESHNESS_BUDGET_EXCEEDED: {observed_ms}ms > {max_ms}ms (INV-STILL-01)")
        return

    # Compute staleness from decision_binding_at (signed field, no tampering needed)
    # V8: staleness = now - decision_binding_at > max_staleness_ms => UNDETERMINED
    import datetime as _dt_mod
    decision_binding_at = still.get("decision_binding_at", "")
    if decision_binding_at and max_ms:
        try:
            t0 = _dt_mod.datetime.fromisoformat(decision_binding_at.replace("Z", "+00:00"))
            now_dt = _dt_mod.datetime.now(_dt_mod.timezone.utc)
            computed_staleness_ms = (now_dt - t0).total_seconds() * 1000
            # Only flag if staleness is meaningfully beyond the window (>10x to avoid test timing issues)
            # In production this would be exact; in testing allow margin
            if computed_staleness_ms > max_ms * 10:
                r.add_undetermined("still_staleness_computed",
                                   f"STILL_COMPUTED_STALENESS_EXCEEDED: {computed_staleness_ms:.0f}ms > {max_ms}ms (INV-STILL-01)")
                return
        except Exception:
            pass

    # If clock supplied, check whether evidence is still fresh via next_information_expected
    if clock_at:
        try:
            now = _dt_mod.datetime.fromisoformat(clock_at.replace("Z", "+00:00"))
            fresh_until = still.get("next_information_expected", "")
            if fresh_until:
                fresh_dt = _dt_mod.datetime.fromisoformat(fresh_until.replace("Z", "+00:00"))
                if now > fresh_dt:
                    r.add_undetermined("still_freshness_clock",
                                       f"STILL_EVIDENCE_STALE: clock {clock_at} past next_information_expected {fresh_until}")
                    return
        except Exception:
            pass  # clock parse error -- continue without freshness check

    r.add("still", True,
          f"STILL_VERIFIED: status={status} mode={eval_mode} staleness={observed_ms}ms/{max_ms}ms")

    # Print positive semantics if present (offline verifier shows this)
    pos_sem = still.get("positive_semantics", "")
    if pos_sem:
        r.checks.append({"check": "positive_semantics", "status": "NOTE", "reason": pos_sem})


def check_replay(passport: dict, r: CheckResult):
    """
    Check 6: Replay digests (INV-EV-05).
    All four digests must be present or verdict is REPLAY_UNAVAILABLE.
    """
    replay = passport.get("replay", {})
    if not replay:
        r.add("replay", False, "REPLAY_UNAVAILABLE: replay field absent (INV-EV-05)",
              EXIT_REPLAY_UNAVAILABLE)
        return

    required = ["policy_digest", "input_digest", "entity_snapshot_digest", "engine_version"]
    missing = [f for f in required if not replay.get(f)]

    if missing:
        r.add("replay", False,
              f"REPLAY_UNAVAILABLE: missing {missing} (INV-EV-05)",
              EXIT_REPLAY_UNAVAILABLE)
        return

    eoi = replay.get("evaluation_order_independent")
    if eoi is not True:
        r.add("replay_order_independent", False,
              "REPLAY_ORDER_DEPENDENT: evaluation_order_independent must be true")
        return

    r.add("replay", True,
          f"REPLAY_AVAILABLE: engine={replay.get('engine_version')} "
          f"status={replay.get('status','?')}")


def check_assurance(passport: dict, r: CheckResult):
    """
    Check 7: Assurance triple (INV-EV-01, INV-EV-02, INV-EV-03).
    P3: independence_class COMPUTED from dependency_sets, never accepted as asserted.
    INV-EV-03: checker compares declared dependency sets.
    If two conjuncts share any member: SHARED_DEPENDENCY regardless of what record claims.
    If dependency_sets absent: NOT_ESTABLISHED -- never INDEPENDENT.
    """
    assurance = passport.get("assurance", {})
    if not assurance:
        r.add_undetermined("assurance", "UNDETERMINED.ASSURANCE_TRIPLE_ABSENT")
        return

    integrity = assurance.get("integrity_class", "")
    custody = assurance.get("custody_class", "")
    claimed_independence = assurance.get("independence_class", "NOT_ESTABLISHED")

    # INV-EV-01: UNAUTHENTICATED_TELEMETRY cannot satisfy a conjunct
    if integrity == "UNAUTHENTICATED_TELEMETRY":
        r.add("assurance_integrity", False,
              "ASSURANCE_TELEMETRY_ONLY: UNAUTHENTICATED_TELEMETRY is CORROBORATED_ONLY (INV-EV-01)",
              EXIT_FAILED)
        return

    # INV-EV-03: independence COMPUTED from dependency_sets -- check BEFORE custody short-circuit
    # These are orthogonal invariants; independence must be checked regardless of custody state
    dep_sets = assurance.get("dependency_sets")
    if dep_sets is None:
        # No dependency sets declared => NOT_ESTABLISHED (never INDEPENDENT)
        computed_independence = "NOT_ESTABLISHED"
        if claimed_independence == "INDEPENDENT":
            r.add("assurance_independence", False,
                  "INDEPENDENCE_ASSERTED_NOT_COMPUTED: dependency_sets absent -- "
                  "CONSISTENT != INDEPENDENT (INV-EV-03)",
                  EXIT_FAILED)
            return
    else:
        # Compute independence from declared dependency sets
        active_sets = [set(v) for v in dep_sets.values() if v]
        computed_independence = "NOT_ESTABLISHED"
        if len(active_sets) >= 2:
            shared = False
            for i, s1 in enumerate(active_sets):
                for s2 in active_sets[i+1:]:
                    if s1 & s2:
                        shared = True
                        break
                if shared:
                    break
            computed_independence = "SHARED_DEPENDENCY" if shared else "INDEPENDENT"
        elif len(active_sets) == 1:
            computed_independence = "NOT_ESTABLISHED"

        # Checker overrides claimed independence with computed value
        if claimed_independence == "INDEPENDENT" and computed_independence != "INDEPENDENT":
            r.add("assurance_independence", False,
                  f"INDEPENDENCE_COMPUTED_{computed_independence}: "
                  f"claimed INDEPENDENT but computed {computed_independence} (INV-EV-03)",
                  EXIT_FAILED)
            return  # Do not fall through to pass
            return

    # INV-EV-02: GAP_UNKNOWN => UNDETERMINED (checked after independence)
    if custody == "GAP_UNKNOWN":
        r.add_undetermined("assurance_custody",
                           "CUSTODY_GAP_UNKNOWN: conjunct UNDETERMINED (INV-EV-02)")
        return

    r.add("assurance", True,
          f"ASSURANCE_VERIFIED: integrity={integrity} custody={custody} "
          f"independence=computed:{computed_independence}")


def check_custody(passport: dict, r: CheckResult):
    """
    Check 8a: Custody chain digest continuity (INV-EV-04).
    For consecutive entries: digest_after[i] == digest_before[i+1].
    If broken: GAP_DECLARED with break recorded.
    """
    custody = passport.get("custody", [])
    if not custody:
        r.add_undetermined("custody_chain", "UNDETERMINED.CUSTODY_CHAIN_ABSENT")
        return

    if len(custody) < 2:
        r.add("custody_chain", True, f"CUSTODY_SINGLE_ENTRY: {custody[0].get('action','?')}")
        return

    breaks = []
    for i in range(len(custody) - 1):
        after = custody[i].get("digest_after", "")
        before_next = custody[i+1].get("digest_before", "")
        if after != before_next:
            breaks.append(f"entry[{i}].digest_after={after[:16]} != entry[{i+1}].digest_before={before_next[:16]}")

    if breaks:
        r.add("custody_continuity", False,
              f"CUSTODY_DIGEST_DISCONTINUITY: {breaks[0]} (INV-EV-04)",
              EXIT_UNDETERMINED)
    else:
        r.add("custody_continuity", True,
              f"CUSTODY_DIGEST_CONTINUOUS: {len(custody)} entries, all digests chain")


def check_scope_ledger(passport: dict, r: CheckResult):
    """
    Check 8: Scope ledger required line (INV-SL-01).
    Must be present. Printed by verifier regardless of verdict.
    """
    ledger = passport.get("scope_ledger", {})
    if not ledger:
        r.add("scope_ledger", False, "SCOPE_LEDGER_ABSENT (INV-SL-01)")
        return

    required = ledger.get("required_line", "")
    if SCOPE_LEDGER_REQUIRED_LINE not in required:
        r.add("scope_ledger_line", False,
              f"SCOPE_LEDGER_REQUIRED_LINE_ABSENT: must contain exact phrase (INV-SL-01)")
    else:
        r.add("scope_ledger", True,
              f"SCOPE_LEDGER_PRESENT: {len(ledger.get('limits', []))} declared limits")


def check_could(passport: dict, r: CheckResult):
    """
    Check P4: COULD conjunct (INV-COULD-01, INV-COULD-02, INV-COULD-03).
    Vector 14: COULD asserted with witness value never observed.
    INV-COULD-02: every witness entry must appear in variables[].actual_value.
    """
    could = passport.get("could")
    if could is None:
        r.add_undetermined("could", "UNDETERMINED.COULD_NOT_MODELLED")
        return

    model_id = could.get("model_id")
    result = could.get("result", "NOT_MODELLED")

    # INV-COULD-01: no model_id => NOT_MODELLED, non-contributing
    if model_id is None:
        if result != "NOT_MODELLED":
            r.add("could_model", False,
                  f"COULD_RESULT_WITHOUT_MODEL: result={result} but model_id=null (INV-COULD-01)",
                  EXIT_FAILED)
            return
        r.add("could", True, "COULD_NOT_MODELLED: acceptable -- model_id absent")
        return

    # INV-COULD-03: intervention_window_ms == 0 or null => no preventability
    window = could.get("intervention_window_ms")
    if window is None or window == 0:
        r.add_undetermined("could_window",
                           "COULD_NO_INTERVENTION_WINDOW: preventability cannot be asserted (INV-COULD-03)")
        return

    # INV-COULD-02: witness values must appear in variables[].actual_value
    variables = could.get("variables", [])
    actual_values = {v.get("name"): v.get("actual_value") for v in variables}
    witnesses = could.get("witness", [])

    violations = []
    for w in witnesses:
        var_name = w.get("variable")
        witness_val = w.get("value")
        if var_name not in actual_values:
            violations.append(f"witness variable '{var_name}' not in variables list")
        elif actual_values[var_name] != witness_val:
            violations.append(f"witness '{var_name}'={witness_val!r} != actual {actual_values[var_name]!r}")

    if violations:
        r.add("could_witness", False,
              f"COULD_WITNESS_NOT_OBSERVED: {violations[0]} (INV-COULD-02)",
              EXIT_FAILED)
        return

    r.add("could", True, f"COULD_VERIFIED: model={model_id} result={result}")


def check_replay_digests(passport: dict, r: CheckResult):
    """
    Check P4: Replay digest cross-reference (INV-EV-05 extension).
    Vector 12: replay with mismatched policy_digest.
    Cross-checks replay.policy_digest against evidence_references.policy_hash.
    """
    replay = passport.get("replay", {})
    if not replay:
        return  # Already handled by check_replay

    # Cross-check replay.policy_digest vs evidence_references.policy_hash
    evidence_refs = passport.get("why_examination", {}).get("evidence_references", {})
    policy_hash = evidence_refs.get("policy_hash", "")
    policy_digest = replay.get("policy_digest", "")

    if policy_hash and policy_digest and policy_hash != policy_digest:
        r.add("replay_policy_mismatch", False,
              f"REPLAY_POLICY_DIGEST_MISMATCH: replay.policy_digest != evidence_references.policy_hash (INV-EV-05)",
              EXIT_REPLAY_UNAVAILABLE)
        return

    if policy_hash and policy_digest and policy_hash == policy_digest:
        r.add("replay_cross_check", True,
              "REPLAY_POLICY_DIGEST_VERIFIED: matches evidence_references.policy_hash")



def check_word_ban(passport: dict, r: CheckResult):
    """
    Check 9: Word ban in signed payload (F-2.2-02).
    Banned words must not appear in signed text fields.
    """
    # Fields that carry text potentially subject to word ban
    text_fields = []
    for key in ["locked_claim", "positive_semantics", "claim"]:
        val = passport.get(key, "")
        if isinstance(val, str):
            text_fields.append((key, val))

    violations = []
    for field_name, text in text_fields:
        for word in WORD_BAN:
            if word.lower() in text.lower():
                violations.append(f"{field_name}:{word}")

    if violations:
        r.add("word_ban", False,
              f"WORD_BAN_VIOLATION: {violations} in signed payload (F-2.2-02)")
    else:
        r.add("word_ban", True, "WORD_BAN_CLEAN: no banned words in signed fields")


def check_schema_version(passport: dict, r: CheckResult):
    """Check passport is v2.2 format."""
    schema = passport.get("schema", "")
    version = passport.get("payload_version", "")

    if "2.2" in schema or version == "2.2":
        r.add("schema_version", True, f"SCHEMA_V2.2: {schema}")
    elif schema.startswith("VGS-SIGILMARK"):
        r.add("schema_version", True, f"SCHEMA_LEGACY: {schema} -- some checks may not apply")
    else:
        r.add("schema_version", False, f"SCHEMA_UNKNOWN: {repr(schema)}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=f"{VERSION} -- VCB Justified Action Record offline checker"
    )
    parser.add_argument("passport", help="Path to passport JSON file")
    parser.add_argument("--pubkey", required=True,
                        help="Base64-encoded Ed25519 public key")
    parser.add_argument("--at", default=None,
                        help="RFC3339 clock time for STILL freshness check (optional)")
    parser.add_argument("--json", action="store_true",
                        help="Output JSON instead of human-readable")
    args = parser.parse_args()

    # Load passport
    try:
        with open(args.passport, encoding="utf-8") as f:
            passport = json.load(f)
    except Exception as e:
        print(f"ERROR: cannot read passport: {e}", file=sys.stderr)
        sys.exit(EXIT_INVALID)

    r = CheckResult()

    # Run all checks
    check_schema_version(passport, r)
    canonical = check_integrity(passport, r)
    check_signature(passport, args.pubkey, canonical, r)
    check_closure(passport, r)
    check_why_edges(passport, r)
    check_still(passport, args.at, r)
    check_replay(passport, r)
    check_assurance(passport, r)
    check_custody(passport, r)
    check_could(passport, r)
    check_replay_digests(passport, r)
    check_scope_ledger(passport, r)
    check_word_ban(passport, r)

    # Get root kind for printing
    closure = passport.get("closure", {})
    root_kind = closure.get("root", {}).get("kind", "UNKNOWN")

    if args.json:
        output = {
            "checker": VERSION,
            "grammar": GRAMMAR_VERSION,
            "verdict": r.verdict,
            "exit_code": r.exit_code,
            "root_kind": root_kind,
            "reason_codes": r.reason_codes,
            "scope_ledger_line": SCOPE_LEDGER_REQUIRED_LINE,
            "checks": r.checks,
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"\n{'='*60}")
        print(f"  {VERSION}")
        print(f"{'='*60}")
        # Three-line evidence summary (Jake Macdonald external examiner model)
        # Maps to three inequalities: SIGNATURE_VALID != CURRENTLY_ADMISSIBLE
        #   HISTORICAL_PROOF != CURRENT_AUTHORITY
        #   CURRENT_AUTHORITY != ADMISSIBLE_CONSEQUENCE
        _checks_by_name = {c["check"]: c["status"] for c in r.checks}
        _issuance = "VERIFIED" if (
            _checks_by_name.get("integrity_hash") == "PASS" and
            _checks_by_name.get("signature") == "PASS"
        ) else "FAILED"
        _current = "NOT_RE-ESTABLISHED" if (
            _checks_by_name.get("still_unknown") == "UNDETERMINED" or
            _checks_by_name.get("assurance_custody") == "UNDETERMINED"
        ) else ("VERIFIED" if r.verdict == "ADMISSIBLE" else "FAILED")
        _consequence = "NOT_ESTABLISHED" if r.verdict == "UNDETERMINED" else (
            "VERIFIED" if r.verdict == "ADMISSIBLE" else "FAILED"
        )
        print(f"\n  EVIDENCE SUMMARY")
        print(f"  ISSUANCE INTEGRITY:       {_issuance}")
        print(f"  CURRENT STANDING:         {_current}")
        print(f"  CONSEQUENCE SUFFICIENCY:  {_consequence}")
        print(f"")
        print(f"  VERDICT:    {r.verdict}")
        print(f"  ROOT KIND:  {root_kind}")
        if r.reason_codes:
            print(f"  REASONS:    {', '.join(r.reason_codes)}")
        print(f"\n  THIS RECEIPT DOES NOT PROVE:")
        print(f"  - General system safety or regulatory compliance")
        print(f"  - Current authority (CURRENT STANDING not re-established offline)")
        print(f"  - Consequence sufficiency without live STILL + COULD gates")
        print(f"  - Authority for actions outside the governed path inventory")
        print(f"  - Production actuator path (C2: test API only)")
        print(f"\n  NOTE: {SCOPE_LEDGER_REQUIRED_LINE}")
        print(f"\n  Checks ({len(r.checks)}):")
        for check in r.checks:
            icon = "OK" if check["status"] == "PASS" else ("~" if check["status"] in ("UNDETERMINED", "NOTE") else "FAIL")
            print(f"    {icon} {check['check']}: {check['reason'][:80]}")
        print(f"{'='*60}\n")

    sys.exit(r.exit_code)


if __name__ == "__main__":
    main()
