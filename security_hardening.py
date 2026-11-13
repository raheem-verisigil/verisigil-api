"""Idempotent source repair for VeriSigil proof verification and public credential disclosure."""
from pathlib import Path
import base64
import os
import re

root = Path(__file__).resolve().parent
main_path = root / "main.py"
src = main_path.read_text(encoding="utf-8")

# The known public demo tokens are represented as base64 so this patch never republishes them.
tokens = [
    base64.b64decode("dnMtc2FuZGJveC1kZW1vLTIwMjZi").decode(),
    base64.b64decode("dnMtc2FuZGJveC1kZW1vLTIwMjY=").decode(),
    base64.b64decode("dmVyaXNpZ2lsLXNlY3JldC0yMDI2").decode(),
]
legacy_public_key = base64.b64decode("VnJUM0pOOGlTS1BvTmt5eU9hbkNFdGZLVWR2b0lUeVh5bDI0RkNuRCtqQT0=").decode()

# Remove the permanent demo keys from the authentication allow-list.
for token in tokens[:2]:
    src = re.sub(r"(?m)^\s*['\"]" + re.escape(token) + r"['\"].*\n", "", src)
src = src.replace(legacy_public_key, "PUBLIC_KEY_B64")

# Replace the legacy verifier with the active runtime key and key revocation handling.
start_marker = '@app.post("/v1/proof/verify", tags=["Public Proof Surface"])'
end_marker = '@app.get("/v1/proof/public-key", tags=["Public Proof Surface"])'
if start_marker in src:
    start = src.index(start_marker)
    end = src.index(end_marker, start)
    src = src[:start] + '''@app.post("/v1/proof/verify", tags=["Public Proof Surface"])
async def proof_verify_record(payload: dict, signature: str = "", key_id: Optional[str] = None):
    """Verify a sealed record against the active runtime Ed25519 key. No auth required."""
    from proof_verification import verify_ed25519_payload, public_key_id

    public_key = base64.b64encode(bytes(_VERIFY_KEY)).decode("ascii")
    revoked_ids = {
        item.strip() for item in os.environ.get("ED25519_REVOKED_KEY_IDS", "").split(",")
        if item.strip()
    }
    outcome = verify_ed25519_payload(
        payload=payload, signature=signature, public_key_b64=public_key,
        key_id=key_id, revoked_key_ids=revoked_ids,
    )
    return {
        "result": outcome["result"], "message": outcome["message"],
        "public_key": public_key, "key_id": public_key_id(public_key),
        "algorithm": "Ed25519",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


''' + src[end:]
elif "from proof_verification import verify_ed25519_payload" not in src:
    raise SystemExit("Legacy proof verification route not found")

# Replace credential disclosures in public examples with inert guidance.
for token in tokens:
    src = src.replace(token, "[REDACTED_SHARED_DEMO_CREDENTIAL]")
src = src.replace(
    'headers={"X-API-Key": "[REDACTED_SHARED_DEMO_CREDENTIAL]"}',
    'headers={"X-API-Key": os.environ.get("VERISIGIL_TEST_API_KEY", "")}'
)
main_path.write_text(src, encoding="utf-8")

# Public endpoint runner uses only a private CI/test environment variable.
p = root / "test_public_endpoints.py"
if p.exists():
    s = p.read_text(encoding="utf-8")
    if "import os" not in s:
        s = s.replace("import sys", "import sys" + chr(10) + "import os", 1)
    s = re.sub(r"(?m)^SANDBOX_KEY\s*=.*$", 'SANDBOX_KEY = os.environ.get("VERISIGIL_TEST_API_KEY", "")', s)
    s = s.replace('''    if auth:
        headers["x-api-key"] = SANDBOX_KEY
''', '''    if auth:
        if not SANDBOX_KEY:
            raise RuntimeError("Set VERISIGIL_TEST_API_KEY in the private test environment")
        headers["x-api-key"] = SANDBOX_KEY
''')
    p.write_text(s, encoding="utf-8")

# Remove stale backup code and explicitly declare the verifier dependency.
(root / "main.py.bak").unlink(missing_ok=True)
req = root / "requirements.txt"
r = req.read_text(encoding="utf-8")
if "cryptography" not in r.lower():
    req.write_text(r.rstrip() + chr(10) + "cryptography>=42.0.0" + chr(10), encoding="utf-8")

# Replace demo values in other Python examples with private environment lookups.
for p in root.rglob("*.py"):
    if p.name in {"main.py", "test_public_endpoints.py", "proof_verification.py"}:
        continue
    s = p.read_text(encoding="utf-8", errors="ignore")
    before = s
    s = s.replace('"' + tokens[0] + '"', 'os.environ.get("VERISIGIL_TEST_API_KEY", "")')
    s = s.replace('"' + tokens[1] + '"', 'os.environ.get("VERISIGIL_TEST_API_KEY", "")')
    s = s.replace('"' + tokens[2] + '"', 'os.environ.get("VERISIGIL_API_KEY", "")')
    if s != before:
        if "os.environ.get(" in s and not re.search(r"(?m)^import os$", s):
            lines = s.splitlines()
            if lines and lines[0].startswith('"""'):
                close = next((i for i in range(1, len(lines)) if lines[i].startswith('"""')), 0)
                lines.insert(close + 1, "import os")
            else:
                lines.insert(0, "import os")
            s = chr(10).join(lines) + chr(10)
        p.write_text(s, encoding="utf-8")

# Remove public default credentials and derive the auxiliary key from the configured signer.
p = root / "resource_governance.py"
if p.exists():
    s = p.read_text(encoding="utf-8")
    s = s.replace('VERISIGIL_API_KEY = os.environ.get("VERISIGIL_API_KEY", "' + tokens[2] + '")',
                  'VERISIGIL_API_KEY = os.environ.get("VERISIGIL_API_KEY", "")')
    s = s.replace('SANDBOX_KEY = os.environ.get("SANDBOX_API_KEY", "' + tokens[1] + '")',
                  'SANDBOX_KEY = os.environ.get("SANDBOX_API_KEY", "")')
    s = s.replace('PUBLIC_VERIFY_KEY = "' + legacy_public_key + '"',
                  '''_private_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(ED25519_KEY_B64))
PUBLIC_VERIFY_KEY = base64.b64encode(_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,
)).decode("ascii")''')
    p.write_text(s, encoding="utf-8")

# Remove credential literals from text documentation and archived test output.
for p in root.rglob("*"):
    if not p.is_file() or "__pycache__" in p.parts or p.suffix == ".py":
        continue
    try:
        s = p.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        continue
    for token in tokens:
        s = s.replace(token, "[REDACTED_SHARED_DEMO_CREDENTIAL]")
    p.write_text(s, encoding="utf-8")

print("VeriSigil hardening source patch applied.")
