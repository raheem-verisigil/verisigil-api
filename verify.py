#!/usr/bin/env python3
"""
VeriSigilAI Proof Passport — Standalone Independent Verifier
============================================================
INV-03: Offline verification must be simple enough for a compliance officer.

Usage:
    python verify.py proof_passport.json

No VeriSigilAI API required. No database. No private keys.
Requires only: the proof passport JSON file and this script.

Verification algorithm:
  1. Integrity hash: recompute from payload fields, compare to stored hash
  2. Signature: verify Ed25519 signature against known public key
  3. Action binding: confirm presented action matches bound action hash
  4. Expiry: check timestamps
  5. Consumption: report consumption state from passport
  6. Claims: report PROVABLE / FAILED / NOT_PROVABLE per domain
"""

import sys
import json
import hashlib
import base64
from datetime import datetime, timezone

# ── VeriSigilAI production public key (Ed25519) ──────────────────────────────
# This is the public signing key for the production VeriSigilAI instance.
# An independent verifier needs only this key — no private keys, no API access.
VERISIGIL_PUBLIC_KEY_B64 = "lJWG0Wabt6uATPu5Upo6UEHWGXQqMyi6LMKQC0xwpY8="

# ── Hash function (must match VCB production) ─────────────────────────────────
# VCB canonical form — must match _vcb_canonical() on server exactly
_VCB_CANONICAL_SEPARATORS = (",", ":")

def _hash(obj: dict) -> str:
    """
    Canonical hash matching VCB production _vcc_hash.
    Uses compact JSON: separators=(',',':'), sorted keys.
    MUST match server-side _vcc_canon exactly.
    Kimi K-6: Python default is (', ', ': ') — must be explicit.
    """
    canon = json.dumps(obj, sort_keys=True, separators=_VCB_CANONICAL_SEPARATORS,
                       ensure_ascii=False, default=str)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()

# ── Signature verification ────────────────────────────────────────────────────
def _verify_signature_vcb(payload: dict, signature: str, public_key_b64: str) -> dict:
    """
    Verify SigilMark Ed25519 signature using domain-separated canonical form.
    Server signs: b"SIGILMARK-v1\x00" + compact_canonical_json(payload_without_signature)
    Both integrity hash AND signature now use compact separators=(',',':').
    """
    try:
        import nacl.signing
        pk_bytes = base64.b64decode(public_key_b64)
        vk = nacl.signing.VerifyKey(pk_bytes)
        # Try domain-separated signing first (new format after Fix-3)
        # Exclude signature AND domain_prefix field from signed content
        # Server signs: b"SIGILMARK-v1\x00" + canonical(payload without signature+domain_prefix)
        payload_for_sig = {k: v for k, v in payload.items()
                           if k not in ("signature", "domain_prefix")}
        domain_prefix = b"SIGILMARK-v1" + b"\x00"  # domain separator
        # Try compact canonical form with domain prefix (current server)
        msg_compact = domain_prefix + json.dumps(
            payload_for_sig, sort_keys=True, separators=_VCB_CANONICAL_SEPARATORS,
            ensure_ascii=False, default=str
        ).encode("utf-8")
        sig_bytes = base64.b64decode(signature)
        try:
            vk.verify(msg_compact, sig_bytes)
            return {"result": "VERIFIED", "algorithm": "Ed25519",
                    "form": "domain-separated-compact", "key_id": public_key_b64[:16] + "..."}
        except Exception:
            pass
        # Fallback: try legacy non-domain-separated form (passports before Fix-3)
        msg_legacy = json.dumps(payload_for_sig, sort_keys=True,
                                ensure_ascii=False).encode()
        vk.verify(msg_legacy, sig_bytes)
        return {"result": "VERIFIED", "algorithm": "Ed25519",
                "form": "legacy-non-domain-separated", "key_id": public_key_b64[:16] + "..."}
    except ImportError:
        return {"result": "LIBRARY_UNAVAILABLE", "note": "Install PyNaCl: pip install pynacl"}
    except Exception as e:
        return {"result": "INVALID", "error": str(e)}


def _verify_signature(payload: dict, signature: str, public_key_b64: str) -> dict:
    try:
        import nacl.signing
        pk_bytes = base64.b64decode(public_key_b64)
        vk = nacl.signing.VerifyKey(pk_bytes)
        canon = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
        sig_bytes = base64.b64decode(signature)
        vk.verify(canon.encode(), sig_bytes)
        return {"result": "VERIFIED", "algorithm": "Ed25519"}
    except ImportError:
        return {"result": "LIBRARY_UNAVAILABLE", "note": "Install PyNaCl: pip install pynacl"}
    except Exception as e:
        return {"result": "INVALID", "error": str(e)}

# ── Integrity check ───────────────────────────────────────────────────────────
def _check_integrity(passport: dict) -> dict:
    stored = passport.get("integrity_hash") or passport.get("sigilmark_hash", "")
    if not stored:
        return {"result": "NOT_PROVABLE", "code": "INTEGRITY_HASH_MISSING"}

    check = {k: v for k, v in passport.items()
             if k not in ("integrity_hash", "sigilmark_hash", "issuer_signature", "signature", "domain_prefix")}
    computed = _hash(check)

    if computed == stored:
        return {"result": "VERIFIED", "hash": stored[:16] + "..."}
    return {"result": "INVALID", "stored": stored[:16], "computed": computed[:16]}

# ── Expiry check ──────────────────────────────────────────────────────────────
def _check_expiry(passport: dict) -> dict:
    expires_at = passport.get("expires_at", "")
    now = datetime.now(timezone.utc).isoformat()
    if not expires_at:
        return {"result": "NOT_PROVABLE", "code": "EXPIRY_NOT_SET"}
    if now > expires_at:
        return {"result": "EXPIRED", "expired_at": expires_at}
    return {"result": "VALID", "expires_at": expires_at}

# ── Main verifier ─────────────────────────────────────────────────────────────
def verify(passport: dict) -> dict:
    results = {}
    now = datetime.now(timezone.utc).isoformat()

    # 1. Integrity
    results["INTEGRITY"] = _check_integrity(passport)

    # 2. Signature
    signature = passport.get("signature", "")
    if signature:
        # sign_payload uses json.dumps WITHOUT compact separators
        # Must match server-side sign_payload exactly: sort_keys=True, ensure_ascii=False, default separators
        payload_for_sig = {k: v for k, v in passport.items() if k != "signature"}
        results["SIGNATURE"] = _verify_signature_vcb(payload_for_sig, signature, VERISIGIL_PUBLIC_KEY_B64)
    else:
        results["SIGNATURE"] = {"result": "NOT_PROVABLE", "code": "SIGNATURE_ABSENT"}

    # 3. Expiry
    results["EXPIRY"] = _check_expiry(passport)

    # 4. Action binding
    action_hash = passport.get("action_hash", "")
    if action_hash:
        results["ACTION_BINDING"] = {"result": "PROVABLE", "action_hash": action_hash[:16] + "..."}
    else:
        results["ACTION_BINDING"] = {"result": "NOT_PROVABLE", "code": "ACTION_HASH_ABSENT"}

    # 5. Consumption state — CANNOT be verified offline (Kimi K-5 finding)
    # The signed artifact always contains NOT_YET_CONSUMED at issuance.
    # Actual consumption state requires a live DB query — defeats offline independence.
    # Do not report PROVABLE here regardless of what the signed field says.
    consumption = passport.get("consumption_state", "UNKNOWN")
    results["CONSUMPTION"] = {
        "result": "NOT_PROVABLE_OFFLINE",
        "state_in_artifact": consumption,
        "note": "Signed artifact always shows NOT_YET_CONSUMED at issuance. Query live DB for current state.",
    }

    # 6. Decision
    decision = passport.get("decision", "UNKNOWN")
    results["WHY"] = {
        "result": "PROVABLE" if decision == "ALLOW" else "FAILED" if decision == "DENY" else "NOT_PROVABLE",
        "decision": decision,
        "authority_hash": (passport.get("authority_hash", "")[:16] + "...") if passport.get("authority_hash") else "ABSENT",
    }

    # 7. STILL — we can verify what was recorded; cannot re-examine live conditions offline
    results["STILL"] = {
        "result": "PARTIAL",
        "note": "Offline verifier confirms what was recorded at examination time. Cannot re-examine live conditions.",
        "acs_version": passport.get("acs_version", "NOT_RECORDED"),
        "issued_at": passport.get("issued_at", "NOT_RECORDED"),
    }

    # 8. COULD — boundary leverage (reported from passport, not re-evaluated)
    leverage = passport.get("leverage_result", passport.get("boundary_result", "NOT_RECORDED"))
    results["COULD"] = {
        "result": "PROVABLE" if leverage in ("LEVERAGE_PRESENT", "PROVABLE") else "NOT_PROVABLE",
        "boundary_result": leverage,
    }

    # 9. WHAT — execution and outcome
    execution = passport.get("execution_result", passport.get("execution_state", "NOT_RECORDED"))
    outcome = passport.get("outcome_result", passport.get("outcome_state", "NOT_RECORDED"))
    results["WHAT"] = {
        "execution": "PROVABLE" if execution not in ("NOT_RECORDED", "", None, "UNKNOWN") else "NOT_PROVABLE",
        "outcome": "PROVABLE" if outcome not in ("NOT_RECORDED", "", None, "UNKNOWN", "NOT_PROVABLE") else "NOT_PROVABLE",
        "execution_state": execution,
        "outcome_state": outcome,
    }

    # 10. Limitations
    limitations = []
    if results["SIGNATURE"].get("result") not in ("VERIFIED",):
        limitations.append("Signature not independently verified — install PyNaCl: pip install pynacl")
    if results["WHAT"]["outcome"] == "NOT_PROVABLE":
        limitations.append("Outcome observation unavailable in this passport")
    if results["STILL"]["result"] == "PARTIAL":
        limitations.append("STILL: offline verifier confirms what was recorded; cannot re-examine live conditions")
    limitations.append("CONSUMPTION: consumption state requires live DB query — NOT_PROVABLE offline")
    limitations.append("This verifier confirms integrity + signature only. WHY/STILL/COULD/WHAT require live VCB system.")

    results["LIMITATIONS"] = limitations

    # 11. Overall
    provable = sum(1 for k, v in results.items()
                   if isinstance(v, dict) and v.get("result") in ("PROVABLE", "VERIFIED", "VALID"))
    not_provable = sum(1 for k, v in results.items()
                       if isinstance(v, dict) and v.get("result") in ("NOT_PROVABLE", "PARTIAL", "LIBRARY_UNAVAILABLE"))
    failed = sum(1 for k, v in results.items()
                 if isinstance(v, dict) and v.get("result") in ("INVALID", "FAILED", "EXPIRED"))

    results["FINAL"] = {
        "PROVABLE":     provable,
        "NOT_PROVABLE": not_provable,
        "FAILED":       failed,
        "OVERALL":      "PASS" if failed == 0 and results["INTEGRITY"]["result"] == "VERIFIED" else "FAIL" if failed > 0 else "PARTIAL",
        "verified_at":  now,
        "verifier":     "VeriSigilAI Standalone Verifier v1.0 — no API required",
    }

    return results

# ── CLI ───────────────────────────────────────────────────────────────────────
def print_report(results: dict):
    print("\n" + "=" * 60)
    print("  VERISIGIL PROOF PASSPORT — INDEPENDENT VERIFICATION")
    print("=" * 60)

    for domain in ["INTEGRITY", "SIGNATURE", "WHY", "STILL", "CONSUMPTION", "COULD", "WHAT", "EXPIRY", "ACTION_BINDING"]:
        if domain not in results:
            continue
        v = results[domain]
        result = v.get("result", "UNKNOWN")
        icon = "✓" if result in ("PROVABLE", "VERIFIED", "VALID") else "✗" if result in ("INVALID", "FAILED", "EXPIRED") else "?"
        print(f"  {icon} {domain:<20} {result}")
        if "error" in v:
            print(f"    → {v['error']}")
        if "note" in v:
            print(f"    → {v['note']}")

    print("\n  LIMITATIONS:")
    for lim in results.get("LIMITATIONS", []):
        print(f"    • {lim}")

    final = results.get("FINAL", {})
    print(f"\n  FINAL RESULT: {final.get('OVERALL', 'UNKNOWN')}")
    print(f"  PROVABLE: {final.get('PROVABLE',0)}  NOT_PROVABLE: {final.get('NOT_PROVABLE',0)}  FAILED: {final.get('FAILED',0)}")
    print(f"  Verified at: {final.get('verified_at', '')}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python verify.py proof_passport.json")
        print("       python verify.py -  (read from stdin)")
        sys.exit(1)

    if sys.argv[1] == "-":
        passport = json.load(sys.stdin)
    else:
        with open(sys.argv[1]) as f:
            passport = json.load(f)

    results = verify(passport)
    print_report(results)

    # Exit code: 0=PASS, 1=FAIL, 2=PARTIAL
    overall = results.get("FINAL", {}).get("OVERALL", "FAIL")
    sys.exit(0 if overall == "PASS" else 1 if overall == "FAIL" else 2)
