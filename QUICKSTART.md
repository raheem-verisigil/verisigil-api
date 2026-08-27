# VCB jar-verify — External Portability Test
**10-minute guide. No prior context required.**

---

## What jar_verify.py Establishes — and What It Does Not

**When jar_verify.py returns INTEGRITY_VERIFIED and SIGNATURE_VERIFIED:**
- The artifact's canonical bytes match the committed integrity hash
- The artifact was signed by the holder of the corresponding private key
- The artifact has not been altered since signing

**When jar_verify.py returns UNDETERMINED:**
- One or more governance conditions (STILL, custody, COULD) could not be independently re-established from the artifact alone
- This is the expected and correct result for an offline verifier
- UNDETERMINED is not an error — it is the verifier refusing to manufacture certainty about conditions it cannot independently verify

**What jar_verify.py does NOT establish:**
- That the action described was actually admissible at execution time
- That the authority was currently valid at the time of consequence
- That all possible execution paths were governed
- That production money moved or a real consequence occurred
- That the system is proof against all deployment configurations

---

## What This Tests
You will verify that a passport issued by the VCB production API is:
- Cryptographically signed by the VCB signing key
- Integrity-protected (SHA-256 over RFC 8785 canonical form)
- Independently verifiable — no network access needed after the initial fetch

---

## Prerequisites
- Python 3.9+
- pip

```bash
pip install pynacl rfc8785
```

---

## Step 1 — Get the checker
```bash
git clone https://github.com/raheem-verisigil/verisigil-api.git
cd verisigil-api
```
Or download jar_verify.py directly from the repo.

---

## Step 2 — Get a fresh passport from production

DEMO KEY NOTE: The key used below (verisigil-secret-2026) is a deliberately
limited demonstration key. It provides read-only access to public verification
endpoints only. It has no access to consequential production authority, seal
endpoints, or administrative functions. It is intentionally published to support
independent verification of VCB's public evidence surface.
Do not use this key for any production purpose.

### Bash / Linux / macOS
```bash
curl -s -X POST https://verisigil-api-production.up.railway.app/v1/vcb/seal \
  -H "X-API-Key: verisigil-secret-2026" \
  -H "Content-Type: application/json" \
  -d '{"vcb_decision":{"decision":"ALLOW","action_hash":"abc123def456abc123def456abc123def456abc123def456abc123def456abc1","authority_hash":"def456abc123def456abc123def456abc123def456abc123def456abc123def4","policy_hash":"aaa111bbb222aaa111bbb222aaa111bbb222aaa111bbb222aaa111bbb222aaa1","state_hash":"bbb222ccc333bbb222ccc333bbb222ccc333bbb222ccc333bbb222ccc333bbb2","consequence_type":"PAYMENT"},"action":{"type":"payment","amount":5000,"vendor":"VENDOR-A"},"enforcement_point":"payment-boundary-v1","ttl_seconds":86400}' > passport.json
```

### Windows PowerShell
```powershell
$body = '{"vcb_decision":{"decision":"ALLOW","action_hash":"abc123def456abc123def456abc123def456abc123def456abc123def456abc1","authority_hash":"def456abc123def456abc123def456abc123def456abc123def456abc123def4","policy_hash":"aaa111bbb222aaa111bbb222aaa111bbb222aaa111bbb222aaa111bbb222aaa1","state_hash":"bbb222ccc333bbb222ccc333bbb222ccc333bbb222ccc333bbb222ccc333bbb2","consequence_type":"PAYMENT"},"action":{"type":"payment","amount":5000,"vendor":"VENDOR-A"},"enforcement_point":"payment-boundary-v1","ttl_seconds":86400}'

Invoke-RestMethod -Method Post `
  -Uri "https://verisigil-api-production.up.railway.app/v1/vcb/seal" `
  -Headers @{"X-API-Key"="verisigil-secret-2026"; "Content-Type"="application/json"} `
  -Body $body | ConvertTo-Json -Depth 20 | Out-File -Encoding utf8 passport.json
```

### Windows curl (Git Bash or WSL)
```bash
curl -s -X POST https://verisigil-api-production.up.railway.app/v1/vcb/seal \
  -H "X-API-Key: verisigil-secret-2026" \
  -H "Content-Type: application/json" \
  -d "{\"vcb_decision\":{\"decision\":\"ALLOW\",\"action_hash\":\"abc123def456abc123def456abc123def456abc123def456abc123def456abc1\",\"authority_hash\":\"def456abc123def456abc123def456abc123def456abc123def456abc123def4\",\"policy_hash\":\"aaa111bbb222aaa111bbb222aaa111bbb222aaa111bbb222aaa111bbb222aaa1\",\"state_hash\":\"bbb222ccc333bbb222ccc333bbb222ccc333bbb222ccc333bbb222ccc333bbb2\",\"consequence_type\":\"PAYMENT\"},\"action\":{\"type\":\"payment\",\"amount\":5000,\"vendor\":\"VENDOR-A\"},\"enforcement_point\":\"payment-boundary-v1\",\"ttl_seconds\":86400}" > passport.json
```

---

## Step 3 — Verify the passport

### Bash / Linux / macOS / Git Bash
```bash
python jar_verify.py passport.json --pubkey lJWG0Wabt6uATPu5Upo6UEHWGXQqMyi6LMKQC0xwpY8=
```

### Windows PowerShell
```powershell
python jar_verify.py passport.json --pubkey lJWG0Wabt6uATPu5Upo6UEHWGXQqMyi6LMKQC0xwpY8=
```

If python is not in your PATH, use the full path:
```powershell
& "C:\Users\<YourName>\AppData\Local\Programs\Python\Python310\python.exe" jar_verify.py passport.json --pubkey lJWG0Wabt6uATPu5Upo6UEHWGXQqMyi6LMKQC0xwpY8=
```

---

## Expected Result

INTEGRITY_VERIFIED and SIGNATURE_VERIFIED are the critical lines.
VERDICT: UNDETERMINED is correct and honest.

The checker runs 15 checks:
1. schema_version
2. integrity_hash
3. signature
4. closure_terminated
5. root_provable_false
6. why_edges_enum
7. actor_chain
8. still_unknown
9. replay
10. assurance_custody
11. custody_continuity
12. could
13. replay_cross_check
14. scope_ledger
15. word_ban

---

## What the Exit Codes Mean

Exit 0: ADMISSIBLE — all conditions met
Exit 1: FAILED — definitive domain violation detected
Exit 2: UNDETERMINED — incomplete evidence (honest, expected for standard passports)
Exit 3: INVALID — structural integrity failure (tampered bytes)
Exit 9: REPLAY_UNAVAILABLE — replay digest mismatch

---

## Conformance Vectors
To test the checker against adversarial inputs, see conformance_vectors.json.

---

## Public Key
lJWG0Wabt6uATPu5Upo6UEHWGXQqMyi6LMKQC0xwpY8=
Ed25519 (PyNaCl VerifyKey). Stable across restarts.

---

## Trusted Computing Base
See TCB.md for the honest boundary: what VCB proves, what it does not prove,
and where the proof stops.

---

Issues? Open a GitHub issue or contact verisigil.ai
