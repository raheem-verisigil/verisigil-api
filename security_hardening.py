"""Apply the VeriSigil proof-verification and exposed-demo-key hardening patch."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent
MAIN = ROOT / "main.py"
source = MAIN.read_text(encoding="utf-8")

old_auth = '''      2. Sandbox keys    — SANDBOX_API_KEY, VERISIGIL_SANDBOX_KEY env vars
      3. CLARA program   — vs-sandbox-demo-2026b (permanent sandbox key)
'''
new_auth = '''      2. Sandbox keys    — operator-provisioned SANDBOX_API_KEY or VERISIGIL_SANDBOX_KEY
      Public/demo credentials are never accepted as authentication secrets.
'''
if old_auth in source:
    source = source.replace(old_auth, new_auth, 1)
old_allow = '''        _normalize(_os.environ.get("VERISIGIL_SANDBOX_KEY", "") or ""),
        "vs-sandbox-demo-2026b",   # CLARA program sandbox key — permanent
        "vs-sandbox-demo-2026",    # Legacy sandbox key
'''
new_allow = '''        _normalize(_os.environ.get("VERISIGIL_SANDBOX_KEY", "") or ""),
'''
if old_allow in source:
    source = source.replace(old_allow, new_allow, 1)
if '"vs-sandbox-demo-2026b"' in source or '"vs-sandbox-demo-2026"' in source:
    raise SystemExit("Hard-coded sandbox credential still present in auth allow-list")

legacy_key = "VrT3JN8iSKPoNkyyOanCEtfKUdvoITyXyl24FCnD+jA="
source = source.replace(
    '"6. Verify Ed25519 signature using VeriSigil public key: ' + legacy_key + '",',
    '"6. Obtain the current Ed25519 public key from GET /v1/proof/public-key and verify the signature.",'
)
source = source.replace(
    "vk = nacl.signing.VerifyKey(base64.b64decode('" + legacy_key + "'))\\nvk.verify(canonical_bytes, sig_bytes)",
    "vk = nacl.signing.VerifyKey(base64.b64decode(public_key_b64))\\nvk.verify(canonical_bytes, sig_bytes)"
)
source = source.replace('"' + legacy_key + '"', "PUBLIC_KEY_B64")

start_marker = '@app.post("/v1/proof/verify", tags=["Public Proof Surface"])'
end_marker = '@app.get("/v1/proof/public-key", tags=["Public Proof Surface"])'
if start_marker in source:
    start = source.index(start_marker)
    end = source.index(end_marker, start)
    replacement = '''@app.post("/v1/proof/verify", tags=["Public Proof Surface"])
async def proof_verify_record(payload: dict, signature: str = "", key_id: Optional[str] = None):
    """Verify a sealed record against the active runtime Ed25519 key. No auth required."""
    from proof_verification import verify_ed25519_payload, public_key_id

    public_key = base64.b64encode(bytes(_VERIFY_KEY)).decode("ascii")
    revoked_ids = {
        item.strip() for item in os.environ.get("ED25519_REVOKED_KEY_IDS", "").split(",")
        if item.strip()
    }
    outcome = verify_ed25519_payload(
        payload=payload,
        signature=signature,
        public_key_b64=public_key,
        key_id=key_id,
        revoked_key_ids=revoked_ids,
    )
    return {
        "result": outcome["result"],
        "message": outcome["message"],
        "public_key": public_key,
        "key_id": public_key_id(public_key),
        "algorithm": "Ed25519",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


'''
    source = source[:start] + replacement + source[end:]
elif "from proof_verification import verify_ed25519_payload" not in source:
    raise SystemExit("Could not locate legacy proof verification route")

source = source.replace("vs-sandbox-demo-2026b", "[REDACTED_SHARED_SANDBOX_CREDENTIAL]")
source = source.replace("vs-sandbox-demo-2026", "[REDACTED_LEGACY_SANDBOX_CREDENTIAL]")
source = source.replace("verisigil-secret-2026", "[REDACTED_SHARED_DEMO_KEY]")
source = source.replace(
    'headers={"X-API-Key": "[REDACTED_SHARED_SANDBOX_CREDENTIAL]"}',
    'headers={"X-API-Key": os.environ.get("VERISIGIL_TEST_API_KEY", "")}'
)
MAIN.write_text(source, encoding="utf-8")

# Test runner credentials are private CI inputs, never repository literals.
p = ROOT / "test_public_endpoints.py"
if p.exists():
    s = p.read_text(encoding="utf-8")
    if "import os" not in s:
        s = s.replace("import sys\\n", "import sys\\nimport os\\n", 1)
    s = s.replace('SANDBOX_KEY= "[REDACTED_SHARED_SANDBOX_CREDENTIAL]"',
                  'SANDBOX_KEY = os.environ.get("VERISIGIL_TEST_API_KEY", "")')
    s = s.replace('''    if auth:
        headers["x-api-key"] = SANDBOX_KEY
''', '''    if auth:
        if not SANDBOX_KEY:
            raise RuntimeError("Set VERISIGIL_TEST_API_KEY in the private test environment")
        headers["x-api-key"] = SANDBOX_KEY
''')
    p.write_text(s, encoding="utf-8")

# Remove the stale backup source file so it cannot be mistaken for deployable code.
(ROOT / "main.py.bak").unlink(missing_ok=True)

# Make the verifier's crypto dependency explicit.
req = ROOT / "requirements.txt"
requirements = req.read_text(encoding="utf-8")
if "cryptography" not in requirements.lower():
    req.write_text(requirements.rstrip() + "\\ncryptography>=42.0.0\\n", encoding="utf-8")

# Replace exposed demo credentials in Python examples with private env lookups.
for p in ROOT.rglob("*.py"):
    if p.name in {"main.py", "test_public_endpoints.py", "proof_verification.py"}:
        continue
    s = p.read_text(encoding="utf-8", errors="ignore")
    original = s
    s = s.replace('"vs-sandbox-demo-2026b"', 'os.environ.get("VERISIGIL_TEST_API_KEY", "")')
    s = s.replace('"vs-sandbox-demo-2026"', 'os.environ.get("VERISIGIL_TEST_API_KEY", "")')
    s = s.replace('"verisigil-secret-2026"', 'os.environ.get("VERISIGIL_API_KEY", "")')
    if s != original:
        if "os.environ.get(" in s and not re.search(r"^import os$", s, re.M):
            s = "import os\\n" + s
        p.write_text(s, encoding="utf-8")

# Documentation and archived test output must not publish credentials.
for p in ROOT.rglob("*"):
    if not p.is_file() or "__pycache__" in p.parts or p.suffix == ".py":
        continue
    try:
        s = p.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        continue
    s = s.replace("vs-sandbox-demo-2026b", "[REDACTED_SHARED_SANDBOX_CREDENTIAL]")
    s = s.replace("vs-sandbox-demo-2026", "[REDACTED_LEGACY_SANDBOX_CREDENTIAL]")
    s = s.replace("verisigil-secret-2026", "[REDACTED_SHARED_DEMO_KEY]")
    p.write_text(s, encoding="utf-8")

print("Security patch applied.")
