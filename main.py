"""
VeriSigil AI — API Server v0.2.0
Real Ed25519 cryptographic signatures + DID resolution + verification endpoint
"""
import base64, hashlib, os, uuid, json
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Header, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import httpx
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")
SIGN_SECRET  = os.environ.get("SIGN_SECRET", "verisigil-secret-2026")

_seed          = hashlib.sha256(SIGN_SECRET.encode()).digest()
SIGNING_KEY    = SigningKey(_seed)
VERIFY_KEY     = SIGNING_KEY.verify_key
PUBLIC_KEY_B64 = base64.b64encode(bytes(VERIFY_KEY)).decode()

security = HTTPBearer(auto_error=False)

app = FastAPI(
    title="VeriSigil AI API",
    description="""
The cryptographic identity and security layer for autonomous AI agents.

## Authentication
Click the **Authorize** button and enter your API key.
Use `verisigil-secret-2026` to issue real stored passports.
Use `demo` or leave blank for demo mode (passports not stored).

## Live API
- Website: https://www.verisigilai.com
- GitHub: https://github.com/raheem-verisigil/verisigil-ai
    """,
    version="0.2.0",
    docs_url="/docs",
)

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

async def db_insert(table, data):
    if not SUPABASE_KEY:
        return data
    async with httpx.AsyncClient() as c:
        r = await c.post(
            f"{SUPABASE_URL}/rest/v1/{table}",
            headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}",
                     "Content-Type": "application/json", "Prefer": "return=representation"},
            json=data, timeout=10)
        result = r.json()
        return result[0] if isinstance(result, list) and result else data

async def db_get(table, field, value):
    if not SUPABASE_KEY:
        return None
    async with httpx.AsyncClient() as c:
        r = await c.get(
            f"{SUPABASE_URL}/rest/v1/{table}?{field}=eq.{value}",
            headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}"},
            timeout=10)
        result = r.json()
        return result[0] if isinstance(result, list) and result else None

async def db_update(table, field, value, data):
    if not SUPABASE_KEY:
        return data
    async with httpx.AsyncClient() as c:
        r = await c.patch(
            f"{SUPABASE_URL}/rest/v1/{table}?{field}=eq.{value}",
            headers={"apikey": SUPABASE_KEY, "Authorization": f"Bearer {SUPABASE_KEY}",
                     "Content-Type": "application/json", "Prefer": "return=representation"},
            json=data, timeout=10)
        result = r.json()
        return result[0] if isinstance(result, list) and result else data

def sign_passport(agent_id, did, issued_at, owner):
    payload = json.dumps({
        "agent_id": agent_id, "did": did, "issued_at": issued_at,
        "owner": owner, "issuer": "https://verisigilai.com",
    }, sort_keys=True).encode()
    signed = SIGNING_KEY.sign(payload)
    return base64.b64encode(signed.signature).decode()

def verify_signature_logic(agent_id, did, issued_at, owner, sig_b64):
    try:
        payload = json.dumps({
            "agent_id": agent_id, "did": did, "issued_at": issued_at,
            "owner": owner, "issuer": "https://verisigilai.com",
        }, sort_keys=True).encode()
        VERIFY_KEY.verify(payload, base64.b64decode(sig_b64))
        return True
    except Exception:
        return False

def make_passport(agent_name, owner, framework, runtime, version, tags, expiry_days):
    _id       = f"vsa_{uuid.uuid4().hex[:12]}"
    slug      = agent_name.lower().replace(" ", "-")
    did       = f"did:web:verisigilai.com:agents:{slug}-{_id[-6:]}"
    now       = datetime.utcnow()
    issued_at = now.isoformat()
    exp       = now + timedelta(days=expiry_days)
    signature = sign_passport(_id, did, issued_at, owner)
    return {
        "agent_id": _id, "agent_name": agent_name, "did": did,
        "public_key": PUBLIC_KEY_B64, "signature": signature,
        "signature_type": "Ed25519", "owner": owner,
        "issuer": "https://verisigilai.com", "status": "ACTIVE",
        "trust_score": 0.97, "eu_risk_class": "LIMITED_RISK", "compliant": True,
        "framework": framework, "runtime": runtime, "version": version, "tags": tags,
        "issued_at": issued_at, "expires_at": exp.isoformat(),
        "threats_detected": 0, "eu_ai_act": True, "gdpr": True,
        "hipaa": False, "soc2": False,
        "certificate_id": f"cert_{uuid.uuid4().hex[:16]}",
        "issued_by": "VeriSigil AI",
    }

def get_api_key(credentials: Optional[HTTPAuthorizationCredentials]) -> str:
    if credentials is None:
        return "demo"
    return credentials.credentials or "demo"

def is_demo(key: str) -> bool:
    return not key or key == "demo"

class IssueReq(BaseModel):
    agent_name: str
    owner: str
    framework: str = "unknown"
    runtime: str = "python"
    version: str = "1.0.0"
    tags: List[str] = []
    expiry_days: int = 365

class VerifyReq(BaseModel):
    agent_id: str

class RevokeReq(BaseModel):
    agent_id: str
    reason: str = "manual_revocation"

class ScanReq(BaseModel):
    code: str
    agent_id: Optional[str] = None

class ComplianceReq(BaseModel):
    agent_id: str
    regulations: List[str] = ["eu_ai_act", "gdpr", "hipaa", "soc2"]

@app.get("/")
async def root():
    return {
        "name": "VeriSigil AI API", "version": "0.2.0", "status": "live",
        "description": "Cryptographic identity and security for autonomous AI agents.",
        "website": "https://www.verisigilai.com", "docs": "/docs",
        "public_key": PUBLIC_KEY_B64, "signature_type": "Ed25519",
        "endpoints": {
            "issue":      "POST /v1/passport/issue",
            "get":        "GET  /v1/passport/{agent_id}",
            "verify":     "POST /v1/passport/verify",
            "verify_get": "GET  /verify/{agent_id}",
            "did":        "GET  /did/{agent_id}",
            "revoke":     "POST /v1/passport/revoke",
            "scan":       "POST /v1/security/scan",
            "compliance": "POST /v1/compliance/check",
        }
    }

@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat(), "version": "0.2.0"}
@app.get("/issue-test")
async def issue_test():
    """
    Test endpoint — issues a real stored passport with no auth needed.
    Proves the database connection works.
    """
    p = make_passport(
        agent_name="verisigil-test-agent",
        owner="raheem@verisigilai.com",
        framework="langchain",
        runtime="python",
        version="1.0.0",
        tags=["test", "verified"],
        expiry_days=365,
    )
    try:
        await db_insert("passports", p)
        p["stored"] = True
    except Exception as e:
        p["error"] = str(e)
    return {"success": True, "passport": p} 
@app.post("/v1/passport/issue")
async def issue(
    req: IssueReq,
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security)
):
    """
    Issue a new cryptographic identity passport signed with Ed25519.

    **Authorization:**
    - Use `verisigil-secret-2026` → passport stored in database
    - Use `demo` or no key → passport generated but NOT stored
    """
    key  = get_api_key(credentials)
    demo = is_demo(key)
    p    = make_passport(req.agent_name, req.owner, req.framework,
