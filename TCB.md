# VCB Trusted Computing Base (TCB)

**Version:** 2.2  
**Date:** 2026-08-25  
**Document:** VGS-TCB-1.0

---

## What Is In the TCB

The VCB trusted computing base is the minimal set of components whose correctness must be trusted for the VCB proof to hold.

| Component | Role | Verification |
|---|---|---|
| Ed25519 signing key (SIGN_SECRET → SHA256 derivation) | Issues unforgeable signatures on passports | Derived deterministically; public key published |
| `_vcb_canonical()` (RFC 8785 JCS) | Produces canonical JSON for signing and hashing | rfc8785 library, version-pinned |
| `_vcc_hash()` (SHA-256 over canonical form) | Produces integrity hash included in signed payload | Standard library hashlib |
| `evaluate_release()` | Gates RELEASE_GRANTED — fail-closed, positive allowlist | Cedar property tests 7/7 pass; DRT 100% agreement |
| `MockPaymentActuator` | Enforces consequence boundary in P4/P5 | VCB invariant test 4/4 pass |

---

## What Is NOT In the TCB

The proof stops where the attributable evidence stops. The following are **not** in the VCB TCB:

| Item | Why Excluded |
|---|---|
| Agent internal reasoning | VCB does not inspect internal model state (INV-EXT-01) |
| Agent memory or chain-of-thought | Opaque execution is compatible with verifiable consequential control |
| Network transport (HTTPS) | Integrity is established by cryptographic hash + signature, not transport |
| Supabase persistence layer | Passports are self-verifying; persistence is not required for verification |
| Railway runtime environment | The passport verifies offline; no trust in the issuer's runtime is required |
| STILL enforcement | Currently scope-limited (STILL_UNKNOWN_STATUS); documented in scope_ledger |
| External policy evaluation | Policy is hashed and included; correctness of policy content is out of scope |

---

## The Honest Proof Boundary

**VCB claims:** Given a passport with `INTEGRITY_VERIFIED` and `SIGNATURE_VERIFIED`, the following are established at the time of issue:

- The exact action hash was examined under the declared authority hash and policy hash
- The signing key was the VCB signing key (verifiable against the published public key)
- The scope_ledger declares what was NOT examined
- The word_ban confirms no epistemic overreach language in the signed payload
- COULD: for P5 passports, the Halpern-Pearl actual causality model was applied to the payment domain

**VCB does not claim:**
- That the declared authority was correctly evaluated (STILL not yet enforced)
- That the policy content was correctly applied (policy hash is present; content examination is out of scope)
- That no other execution path existed (ALTERNATIVES_NOT_MODELLED in scope_ledger)
- That the consequence was executed (WHAT conjunct, post-P6)

---

## External Portability Test (§5.5)

Any party can verify a VCB passport offline using:

1. `jar_verify.py` (from public repo: `github.com/raheem-verisigil/verisigil-api`)
2. Public key: `lJWG0Wabt6uATPu5Upo6UEHWGXQqMyi6LMKQC0xwpY8=`
3. A passport issued by `POST /v1/vcb/seal`

Expected result: `VERDICT: UNDETERMINED` with `INTEGRITY_VERIFIED (rfc8785-jcs-v1)` and `SIGNATURE_VERIFIED (rfc8785-jcs-v1)`.

No network access is required after obtaining the passport. No trust in the issuer is required beyond the public key.

---

## Key Derivation

The signing key is derived deterministically from the `SIGN_SECRET` environment variable:

```
signing_key_bytes = SHA256(SIGN_SECRET.encode("utf-8"))
signing_key = Ed25519SigningKey(signing_key_bytes)
public_key = signing_key.verify_key
```

This ensures the same secret always produces the same key pair. The public key is stable across restarts.

**Published public key:** `lJWG0Wabt6uATPu5Upo6UEHWGXQqMyi6LMKQC0xwpY8=`

---

*"VCB does not claim to prove the entire internal system. It examines the externally attributable conditions required to establish whether a specific consequential transition was admissible, whether those conditions remained valid at commitment, whether the boundary retained leverage, and what can later be established about the outcome. The proof stops where the attributable evidence stops."*
