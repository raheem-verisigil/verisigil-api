# VeriSigil AI — Version A Post (V4/V5 only — safe to post now)

---

We did not start by claiming VeriSigil could govern consequential AI execution.

We started by testing whether the evidence would actually support that claim.

---

Here is what we have independently verified under adversarial conditions on live production infrastructure:

**Receipt integrity + Ed25519 signature** — independently cold-reproduced by an external engineer without guidance. The verifier returned UNDETERMINED where live conditions could not be re-established offline. That is the correct designed behavior. It does not invent authority.

**STILL adversarial suite — 11/11 on live Railway + real Supabase** — revoked authority refused. Expired authority refused. Amount exceeding ceiling refused. Unauthorized vendor refused. Forged caller-supplied standing refused. Unknown mandate returned NOT_PROVABLE (fail-closed, not an error). Confirmed on two independent builds with different instance IDs.

**Seal → Verify → Persist → Retrieve → Tamper** — SigilMark issued on live Railway, verified as VALID, persisted to real Supabase with durability confirmed, retrieved with cache_used=False, and detected as INVALID when a single field was zeroed (INTEGRITY_HASH_INVALID).

**Actuator boundary** — inadmissible paths did not reach the Paystack API (state_mutation=NONE). Admissible paths reached the actuator boundary. The actuator independently verified the commitment rather than trusting upstream state.

**Post-restart durability** — independently confirmed by an external tester who planted an anchor before process start and retrieved it after restart with durability_verified=True.

---

**What we are not claiming:**

- Universal prevention of unauthorized AI actions
- Production-proven with live money
- All deployment paths governed
- Regulatory certification of any kind
- Receipt verification is the same as proving current authority for a live action

---

**What is still open:**

Delegation scope enforcement — fix deployed and 23/23 internal adversarial tests pass. External live confirmation in progress. We will publish that result exactly as it arrives, pass or fail.

---

**What this gives you without trusting us:**

Download any SigilMark. Run jar-verify-0.2.0 with the public key below. You will see UNDETERMINED on STILL and COULD. That is honest behavior, not a failure. An artifact cannot re-establish live standing offline. We do not paper over that.

Public key: `lJWG0Wabt6uATPu5Upo6UEHWGXQqMyi6LMKQC0xwpY8=`

Full evidence report and challenge protocol: [GitHub link]

---

*VeriSigil AI — scoped evidence for a consequence boundary, not a slogan.*

