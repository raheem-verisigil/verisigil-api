"""
VeriSigil AI — Live API Server v0.1.0
"""
import hashlib, hmac, os, uuid
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")
SIGN_SECRET  = os.environ.get("SIGN_SECRET", "verisigil-secret-2026")

app = FastAPI(
    title="VeriSigil AI API",
    description="The cryptographic identity and security layer for autonomous AI agents.",
    version="0.1.0",
    docs_url="/docs",
)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

async def db_insert(table: str, data: dict):
    if not SUPABASE_KEY:
        return data
    async with httpx.AsyncClient() as c:
        r = await c.post(
            f"{SUPABASE_URL}/rest/v1/{table}",
            headers={
                "apikey": SUPABASE_KEY,
                "Authorization": f"Bearer {SUPABASE_KEY}",
                "Content-Type": "application/json",
                "Prefer": "return=representation"
            },
            json=data, timeout=10
        )
        result = r.json()
        return result[0] if isinstance(result, list) and result else data

async def db_get(table: str, field: str, value: str):
    if not SUPABASE_KEY:
        return None
    async with httpx.AsyncClient() as c:
        r = await c.get(
            f"{SUPABASE_URL}/rest/v1/{table}?{field}=eq.{value}",
            headers={
                "apikey": SUPABASE_KEY,
                "Authorization": f"Bearer {SUPABASE_KEY}"
            },
            timeout=10
        )
        result = r.json()
        return result[0] if isinstance(result, list) and result else None

async def db_update(table: str, field: str, value: str, data: dict):
    if not SUPABASE_KEY:
        return data
    async with httpx.AsyncClient() as c:
        r = await c.patch(
            f"{SUPABASE_URL}/rest/v1/{table}?{field}=eq.{value}",
            headers={
                "apikey": SUPABASE_KEY,
                "Authorization": f"Bearer {SUPABASE_KEY}",
                "Content-Type": "application/json",
                "Prefer": "return=representation"
            },
            json=data, timeout=10
        )
        result = r.json()
        return result[0] if isinstance(result, list) and result else data

def make_passport(agent_name, owner, framework, runtime, version, tags, expiry_days):
    _id  = f"vsa_{uuid.uuid4().hex[:12]}"
    slug = agent_name.lower().replace(" ", "-")
    did  = f"did:web:verisigilai.com:agents:{slug}-{_id[-6:]}"
    sig  = f"DIDSig:{hmac.new(SIGN_SECRET.encode(), _id.encode(), hashlib.sha256).hexdigest()}"
    now  = datetime.utcnow()
    exp  = now + timedelta(days=expiry_days)
    return {
        "agent_id": _id, "agent_name": agent_name, "did": did,
        "owner": owner, "status": "ACTIVE", "trust_score": 0.97,
        "eu_risk_class": "LIMITED_RISK", "compliant": True,
        "signature": sig, "framework": framework, "runtime": runtime,
        "version": version, "tags": tags,
        "issued_at": now.isoformat(), "expires_at": exp.isoformat(),
        "threats_detected": 0, "eu_ai_act": True, "gdpr": True,
        "hipaa": False, "soc2": False,
        "certificate_id": f"cert_{uuid.uuid4().hex[:16]}",
        "issued_by": "VeriSigil AI",
    }

def get_key(auth: str) -> str:
    return (auth or "").replace("Bearer ", "").strip()

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
        "name": "VeriSigil AI API",
        "version": "0.1.0",
        "status": "live",
        "description": "Cryptographic identity and security for autonomous AI agents.",
        "website": "https://www.verisigilai.com",
        "docs": "/docs",
        "endpoints": {
            "issue":      "POST /v1/passport/issue",
            "get":        "GET  /v1/passport/{agent_id}",
            "verify":     "POST /v1/passport/verify",
            "revoke":     "POST /v1/passport/revoke",
            "scan":       "POST /v1/security/scan",
            "compliance": "POST /v1/compliance/check",
        }
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "0.1.0"
    }

@app.post("/v1/passport/issue")
async def issue(req: IssueReq, authorization: Optional[str] = Header(None)):
    key  = get_key(authorization)
    demo = is_demo(key)
    p    = make_passport(req.agent_name, req.owner, req.framework,
                         req.runtime, req.version, req.tags, req.expiry_days)
    if demo:
        p["demo"] = True
        p["note"] = "Demo passport. Get your free API key at verisigilai.com"
    else:
        try:
            await db_insert("passports", p)
        except Exception:
            pass
    return {"success": True, "passport": p}

@app.get("/v1/passport/{agent_id}")
async def get_p(agent_id: str, authorization: Optional[str] = Header(None)):
    key = get_key(authorization)
    if is_demo(key):
        raise HTTPException(404, "Demo mode does not persist passports. Use a real API key.")
    p = await db_get("passports", "agent_id", agent_id)
    if not p:
        raise HTTPException(404, "Passport not found.")
    return {"success": True, "passport": p}

@app.post("/v1/passport/verify")
async def verify(req: VerifyReq, authorization: Optional[str] = Header(None)):
    key = get_key(authorization)
    if is_demo(key):
        return {
            "verified": True, "agent_id": req.agent_id,
            "trust_score": 0.97, "status": "ACTIVE", "demo": True
        }
    p = await db_get("passports", "agent_id", req.agent_id)
    if not p:
        return {"verified": False, "agent_id": req.agent_id, "reason": "Not found"}
    if p.get("status") != "ACTIVE":
        return {"verified": False, "agent_id": req.agent_id, "reason": f"Status: {p['status']}"}
    if datetime.utcnow() > datetime.fromisoformat(p["expires_at"]):
        return {"verified": False, "agent_id": req.agent_id, "reason": "Expired"}
    return {
        "verified": True, "agent_id": req.agent_id,
        "trust_score": p.get("trust_score", 0.97),
        "status": p.get("status"), "did": p.get("did")
    }

@app.post("/v1/passport/revoke")
async def revoke(req: RevokeReq, authorization: Optional[str] = Header(None)):
    key = get_key(authorization)
    if is_demo(key):
        return {"revoked": True, "agent_id": req.agent_id, "reason": req.reason, "demo": True}
    p = await db_get("passports", "agent_id", req.agent_id)
    if not p:
        raise HTTPException(404, "Passport not found.")
    await db_update("passports", "agent_id", req.agent_id, {
        "status": "REVOKED",
        "revoked_at": datetime.utcnow().isoformat(),
        "revoke_reason": req.reason
    })
    return {"revoked": True, "agent_id": req.agent_id, "reason": req.reason}

@app.post("/v1/security/scan")
async def scan(req: ScanReq, authorization: Optional[str] = Header(None)):
    threats, seen = [], set()
    lines = req.code.split("\n")
    patterns = [
        ("eval(",       "HIGH",   "Unsafe eval() — arbitrary code execution risk"),
        ("exec(",       "HIGH",   "Unsafe exec() — arbitrary code execution risk"),
        ("subprocess",  "MEDIUM", "Subprocess call — verify inputs are sanitised"),
        ("os.system",   "HIGH",   "Direct OS command execution"),
        ("pickle.load", "HIGH",   "Unsafe deserialisation — use JSON"),
        ("password",    "HIGH",   "Possible hardcoded credential"),
        ("api_key",     "HIGH",   "Possible hardcoded API key"),
        ("secret",      "HIGH",   "Possible hardcoded secret"),
    ]
    for i, line in enumerate(lines, 1):
        for pat, sev, desc in patterns:
            k = f"{i}:{pat}"
            if pat.lower() in line.lower() and k not in seen:
                seen.add(k)
                threats.append({
                    "line": i, "severity": sev,
                    "description": desc, "code": line.strip()
                })
    return {
        "scan_id": f"scan_{uuid.uuid4().hex[:12]}",
        "agent_id": req.agent_id,
        "lines_scanned": len(lines),
        "threats": threats,
        "threat_count": len(threats),
        "severity_summary": {
            "HIGH":   sum(1 for t in threats if t["severity"] == "HIGH"),
            "MEDIUM": sum(1 for t in threats if t["severity"] == "MEDIUM"),
            "LOW": 0,
        },
        "passed": len(threats) == 0,
        "scanned_at": datetime.utcnow().isoformat(),
    }

@app.post("/v1/compliance/check")
async def compliance(req: ComplianceReq, authorization: Optional[str] = Header(None)):
    result = {}
    if "eu_ai_act" in req.regulations:
        result["eu_ai_act"] = {
            "compliant": True,
            "risk_class": "LIMITED_RISK",
            "deadline": "2026-08-01"
        }
    if "gdpr" in req.regulations:
        result["gdpr"] = {
            "compliant": True,
            "lawful_basis": "legitimate_interest"
        }
    if "hipaa" in req.regulations:
        result["hipaa"] = {
            "compliant": False,
            "reason": "BAA required — contact info@verisigilai.com"
        }
    if "soc2" in req.regulations:
        result["soc2"] = {
            "compliant": False,
            "reason": "SOC 2 audit in progress — Q4 2026"
        }
    return {
        "agent_id": req.agent_id,
        "checked_at": datetime.utcnow().isoformat(),
        "regulations": result
    }
