"""Finalize environment-only auxiliary key configuration after the main patch."""
from pathlib import Path
import base64
import re

root = Path(__file__).resolve().parent
p = root / "resource_governance.py"
if p.exists():
    s = p.read_text(encoding="utf-8")
    s = re.sub(r"(?m)^VERISIGIL_API_KEY\s*=.*$", 'VERISIGIL_API_KEY = os.environ.get("VERISIGIL_API_KEY", "")', s)
    s = re.sub(r"(?m)^SANDBOX_KEY\s*=.*$", 'SANDBOX_KEY = os.environ.get("SANDBOX_API_KEY", "")', s)
    legacy = base64.b64decode("VnJUM0pOOGlTS1BvTmt5eU9hbkNFdGZLVWR2b0lUeVh5bDI0RkNuRCtqQT0=").decode()
    dynamic = '''_private_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(ED25519_KEY_B64))
PUBLIC_VERIFY_KEY = base64.b64encode(_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,
)).decode("ascii")'''
    s = re.sub(r'(?m)^PUBLIC_VERIFY_KEY\s*=.*$', dynamic, s)
    p.write_text(s, encoding="utf-8")
print("Auxiliary credential configuration finalized.")
