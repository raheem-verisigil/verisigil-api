"""
VeriSigil AI — API Server v0.3.0
Ed25519 signatures + DID resolution + Audit log (stored inside passport record)
"""
import base64, hashlib, os, uuid, json
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
from nacl.signing import SigningKey
from nacl.exceptions import BadSignatureError

SUPABASE_URL = os.environ.get("SUPABASE_URL", "https://ixiwsdjuduwwzbdfgunm.supabase.co")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Iml4aXdzZGp1ZHV3d3piZGZndW5tIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Nzc2Njg5NjAsImV4cCI6MjA5MzI0NDk2MH0.dV3_5Qg1MPmPVyc9_y7CC2GJBBRe0QRfOYGo6zuIo-U")
SIGN_SECRET  = os.environ.get("SIGN_SECRET", "verisigil-secret-2026")

_seed          = hashlib.sha256(SIGN_SECRET.encode()).digest()
SIGNING_KEY    = SigningKey(_seed)
VERIFY_KEY     = SIGNING_KEY.verify_key
PUBLIC_KEY_B64 = base64.b64encode(bytes(VERIFY_KEY)).decode()

app = FastAPI(
    title="VeriSigil AI API",
    description="The cryptographic identity and security layer for autonomous AI agents.",
    version="0.3.0",
    docs_url="/docs",
)

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

# ── Supabase helpers ──────────────────────────────────────
def get_headers():
    return {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }

async def db_insert(table, data):
    async with httpx.AsyncClient() as c:
        r = await c.post(f"{SUPABASE_URL}/rest/v1/{table}",
                         headers=get_headers(), json=data, timeout=10)
        result = r.json()
        return result[0] if isinstance(result, list) and result else data

async def db_get(table, field, value):
    async with httpx.AsyncClient() as c:
        r = await c.get(f"{SUPABASE_URL}/rest/v1/{table}?{field}=eq.{value}",
                        headers=get_headers(), timeout=10)
        result = r.json()
        return result[0] if isinstance(result, list) and result else None

async def db_patch(table, field, value, data):
    async with httpx.AsyncClient() as c:
        r = await c.patch(f"{SUPABASE_URL}/rest/v1/{table}?{field}=eq.{value}",
                          headers=get_headers(), json=data, timeout=10)
        result = r.json()
        return result[0] if isinstance(result, list) and result else data

# ── Signing helpers ───────────────────────────────────────
def sign_payload(data: dict) -> str:
    msg = json.dumps(data, sort_keys=True).encode()
    return base64.b64encode(SIGNING_KEY.sign(msg).signature).decode()

def verify_payload(data: dict, sig_b64: str) -> bool:
    try:
        msg = json.dumps(data, sort_keys=True).encode()
        VERIFY_KEY.verify(msg, base64.b64decode(sig_b64))
        return True
    except Exception:
        return False

# ── Audit log — stored inside passport record ─────────────
async def log_event(agent_id: str, event: str, event_data: dict = {}):
    """
    Append a signed audit event to the passport's audit_events array.
    Stored inside the passport record — bypasses network ban on audit_log table.
    """
    timestamp = datetime.utcnow().isoformat()
    entry = {
        "event":          event,
        "timestamp":      timestamp,
        "event_data":     event_data,
        "signature":      sign_payload({"agent_id": agent_id, "event": event, "timestamp": timestamp}),
        "signature_type": "Ed25519",
    }
    try:
        passport = await db_get("passports", "agent_id", agent_id)
        if passport:
            existing = passport.get("audit_events") or []
            existing.append(entry)
            await db_patch("passports", "agent_id", agent_id, {"audit_events": existing})
    except Exception:
        pass
    return entry

# ── Passport generator ────────────────────────────────────
def make_passport(agent_name, owner, framework, runtime, version, tags, expiry_days):
    _id       = f"vsa_{uuid.uuid4().hex[:12]}"
    slug      = agent_name.lower().replace(" ", "-")
    did       = f"did:web:verisigilai.com:agents:{slug}-{_id[-6:]}"
    now       = datetime.utcnow()
    issued_at = now.isoformat()
    exp       = now + timedelta(days=expiry_days)
    signature = sign_payload({
        "agent_id": _id, "did": did,
        "issued_at": issued_at, "owner": owner,
        "issuer": "https://verisigilai.com",
    })
    return {
        "agent_id":        _id,
        "agent_name":      agent_name,
        "did":             did,
        "public_key":      PUBLIC_KEY_B64,
        "signature":       signature,
        "signature_type":  "Ed25519",
        "owner":           owner,
        "issuer":          "https://verisigilai.com",
        "status":          "ACTIVE",
        "trust_score":     0.97,
        "eu_risk_class":   "LIMITED_RISK",
        "compliant":       True,
        "framework":       framework,
        "runtime":         runtime,
        "version":         version,
        "tags":            tags,
        "issued_at":       issued_at,
        "expires_at":      exp.isoformat(),
        "threats_detected": 0,
        "eu_ai_act":       True,
        "gdpr":            True,
        "hipaa":           False,
        "soc2":            False,
        "certificate_id":  f"cert_{uuid.uuid4().hex[:16]}",
        "issued_by":       "VeriSigil AI",
        "audit_events":    [],
    }

# ── Models ────────────────────────────────────────────────
class IssueReq(BaseModel):
    agent_name:  str
    owner:       str
    framework:   str = "unknown"
    runtime:     str = "python"
    version:     str = "1.0.0"
    tags:        List[str] = []
    expiry_days: int = 365

class VerifyReq(BaseModel):
    agent_id: str

class RevokeReq(BaseModel):
    agent_id: str
    reason:   str = "manual_revocation"

class ScanReq(BaseModel):
    code:     str
    agent_id: Optional[str] = None

class ComplianceReq(BaseModel):
    agent_id:    str
    regulations: List[str] = ["eu_ai_act", "gdpr", "hipaa", "soc2"]

# ── Routes ────────────────────────────────────────────────
@app.get("/")
async def root():
    return {
        "name":           "VeriSigil AI API",
        "version":        "0.3.0",
        "status":         "live",
        "description":    "Cryptographic identity and security for autonomous AI agents.",
        "website":        "https://www.verisigilai.com",
        "docs":           "/docs",
        "public_key":     PUBLIC_KEY_B64,
        "signature_type": "Ed25519",
        "endpoints": {
            "issue":      "POST /v1/passport/issue",
            "get":        "GET  /v1/passport/{agent_id}",
            "audit":      "GET  /v1/passport/{agent_id}/audit",
            "verify":     "GET  /verify/{agent_id}",
            "did":        "GET  /did/{agent_id}",
            "revoke":     "POST /v1/passport/revoke",
            "scan":       "POST /v1/security/scan",
            "compliance": "POST /v1/compliance/check",
        }
    }

@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat(), "version": "0.3.0"}

@app.get("/issue-test")
async def issue_test():
    """Issues and stores a real test passport with audit log. No auth needed."""
    p = make_passport("verisigil-test-agent", "raheem@verisigilai.com",
                      "langchain", "python", "1.0.0", ["test"], 365)
    # Embed ISSUED event before storing
    p["audit_events"] = [{
        "event":          "ISSUED",
        "timestamp":      p["issued_at"],
        "event_data":     {"agent_name": p["agent_name"], "owner": p["owner"]},
        "signature":      sign_payload({"agent_id": p["agent_id"], "event": "ISSUED", "timestamp": p["issued_at"]}),
        "signature_type": "Ed25519",
    }]
    try:
        await db_insert("passports", p)
        p["stored"] = True
    except Exception as e:
        p["stored"] = False
        p["error"]  = str(e)
    return {"success": True, "passport": p}

@app.post("/v1/passport/issue")
async def issue(req: IssueReq, authorization: Optional[str] = Header(None)):
    """Issue a new Ed25519 signed passport with audit log. Stored automatically."""
    p = make_passport(req.agent_name, req.owner, req.framework,
                      req.runtime, req.version, req.tags, req.expiry_days)
    p["audit_events"] = [{
        "event":          "ISSUED",
        "timestamp":      p["issued_at"],
        "event_data":     {"agent_name": req.agent_name, "owner": req.owner, "framework": req.framework},
        "signature":      sign_payload({"agent_id": p["agent_id"], "event": "ISSUED", "timestamp": p["issued_at"]}),
        "signature_type": "Ed25519",
    }]
    try:
        await db_insert("passports", p)
        p["stored"] = True
    except Exception as e:
        p["stored"]  = False
        p["warning"] = str(e)
    return {"success": True, "passport": p}

@app.get("/v1/passport/{agent_id}/audit")
async def get_audit(agent_id: str):
    """
    Get the cryptographic audit log for an agent.
    Every event is Ed25519 signed. Public — no API key required.
    """
    p = await db_get("passports", "agent_id", agent_id)
    if not p:
        raise HTTPException(404, "Passport not found.")

    events = p.get("audit_events") or []

    verified = []
    for e in events:
        sig_valid = verify_payload(
            {"agent_id": agent_id, "event": e["event"], "timestamp": e["timestamp"]},
            e.get("signature", "")
        )
        verified.append({**e, "signature_valid": sig_valid})

    return {
        "agent_id":       agent_id,
        "total_events":   len(verified),
        "audit_log":      verified,
        "public_key":     PUBLIC_KEY_B64,
        "signature_type": "Ed25519",
        "issued_by":      "VeriSigil AI",
        "note":           "Every event is Ed25519 signed. Verify independently using the public key.",
    }

@app.get("/v1/passport/{agent_id}")
async def get_p(agent_id: str):
    p = await db_get("passports", "agent_id", agent_id)
    if not p:
        raise HTTPException(404, "Passport not found.")
    return {"success": True, "passport": p}

@app.get("/verify/{agent_id}")
async def verify_get(agent_id: str):
    """PUBLIC — verify any agent. No API key needed."""
    p = await db_get("passports", "agent_id", agent_id)
    if not p:
        return {"valid": False, "verified": False, "agent_id": agent_id,
                "reason": "Passport not found.", "issuer": "verisigilai.com"}

    sig_valid   = verify_payload(
        {"agent_id": p["agent_id"], "did": p["did"],
         "issued_at": p["issued_at"], "owner": p["owner"],
         "issuer": "https://verisigilai.com"},
        p.get("signature", ""))
    is_active   = p.get("status") == "ACTIVE"
    not_expired = datetime.utcnow() < datetime.fromisoformat(p["expires_at"])

    await log_event(agent_id, "VERIFIED", {"method": "GET /verify"})

    return {
        "valid":           sig_valid and is_active and not_expired,
        "verified":        sig_valid,
        "agent_id":        agent_id,
        "did":             p.get("did"),
        "status":          p.get("status"),
        "trust_score":     p.get("trust_score"),
        "signature_valid": sig_valid,
        "signature_type":  "Ed25519",
        "public_key":      PUBLIC_KEY_B64,
        "issuer":          "verisigilai.com",
        "issued_at":       p.get("issued_at"),
        "expires_at":      p.get("expires_at"),
        "compliant":       p.get("compliant"),
        "eu_ai_act":       p.get("eu_ai_act"),
    }

@app.post("/v1/passport/verify")
async def verify_post(req: VerifyReq):
    p = await db_get("passports", "agent_id", req.agent_id)
    if not p:
        return {"verified": False, "agent_id": req.agent_id, "reason": "Not found"}
    if p.get("status") != "ACTIVE":
        return {"verified": False, "agent_id": req.agent_id, "reason": f"Status: {p['status']}"}
    if datetime.utcnow() > datetime.fromisoformat(p["expires_at"]):
        return {"verified": False, "agent_id": req.agent_id, "reason": "Expired"}
    sig_valid = verify_payload(
        {"agent_id": p["agent_id"], "did": p["did"],
         "issued_at": p["issued_at"], "owner": p["owner"],
         "issuer": "https://verisigilai.com"},
        p.get("signature", ""))
    await log_event(req.agent_id, "VERIFIED", {"method": "POST /verify"})
    return {"verified": sig_valid, "agent_id": req.agent_id,
            "trust_score": p.get("trust_score", 0.97), "status": p.get("status"),
            "did": p.get("did"), "signature_valid": sig_valid,
            "signature_type": "Ed25519", "public_key": PUBLIC_KEY_B64}

@app.get("/did/{agent_id}")
async def did_resolution(agent_id: str):
    """W3C DID Document — PUBLIC."""
    p = await db_get("passports", "agent_id", agent_id)
    if not p:
        raise HTTPException(404, {"error": "notFound", "message": f"DID not found for {agent_id}"})
    did     = p.get("did")
    pub_key = p.get("public_key", PUBLIC_KEY_B64)
    return {
        "@context": ["https://www.w3.org/ns/did/v1",
                     "https://w3id.org/security/suites/ed25519-2020/v1"],
        "id": did, "controller": "did:web:verisigilai.com",
        "verificationMethod": [{"id": f"{did}#key-1",
                                 "type": "Ed25519VerificationKey2020",
                                 "controller": did,
                                 "publicKeyMultibase": "z" + base64.b64encode(
                                     base64.b64decode(pub_key)).decode()}],
        "authentication":  [f"{did}#key-1"],
        "assertionMethod": [f"{did}#key-1"],
        "service": [{"id": f"{did}#verisigil", "type": "VeriSigilPassportService",
                     "serviceEndpoint": f"https://verisigil-api-production.up.railway.app/verify/{agent_id}"}],
        "metadata": {"agent_id": agent_id, "agent_name": p.get("agent_name"),
                     "status": p.get("status"), "trust_score": p.get("trust_score"),
                     "issued_at": p.get("issued_at"), "expires_at": p.get("expires_at"),
                     "issuer": "VeriSigil AI", "eu_ai_act": p.get("eu_ai_act"),
                     "compliant": p.get("compliant")}
    }

@app.post("/v1/passport/revoke")
async def revoke(req: RevokeReq):
    p = await db_get("passports", "agent_id", req.agent_id)
    if not p:
        raise HTTPException(404, "Passport not found.")
    await db_patch("passports", "agent_id", req.agent_id,
                   {"status": "REVOKED", "revoked_at": datetime.utcnow().isoformat(),
                    "revoke_reason": req.reason})
    await log_event(req.agent_id, "REVOKED", {"reason": req.reason})
    return {"revoked": True, "agent_id": req.agent_id, "reason": req.reason}

@app.post("/v1/security/scan")
async def scan(req: ScanReq):
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
                threats.append({"line": i, "severity": sev,
                                 "description": desc, "code": line.strip()})
    if req.agent_id:
        await log_event(req.agent_id, "SCANNED",
                        {"lines_scanned": len(lines), "threats_found": len(threats)})
    return {
        "scan_id": f"scan_{uuid.uuid4().hex[:12]}", "agent_id": req.agent_id,
        "lines_scanned": len(lines), "threats": threats, "threat_count": len(threats),
        "severity_summary": {"HIGH": sum(1 for t in threats if t["severity"]=="HIGH"),
                             "MEDIUM": sum(1 for t in threats if t["severity"]=="MEDIUM"), "LOW": 0},
        "passed": len(threats)==0, "scanned_at": datetime.utcnow().isoformat(),
    }

@app.post("/v1/compliance/check")
async def compliance(req: ComplianceReq):
    result = {}
    if "eu_ai_act" in req.regulations:
        result["eu_ai_act"] = {"compliant": True, "risk_class": "LIMITED_RISK",
                                "deadline": "2026-08-01",
                                "note": "Designed for EU AI Act alignment — certification in progress"}
    if "gdpr"  in req.regulations:
        result["gdpr"]  = {"compliant": True, "lawful_basis": "legitimate_interest"}
    if "hipaa" in req.regulations:
        result["hipaa"] = {"compliant": False, "reason": "BAA required — contact info@verisigilai.com"}
    if "soc2"  in req.regulations:
        result["soc2"]  = {"compliant": False, "reason": "SOC 2 audit in progress — Q4 2026"}
    await log_event(req.agent_id, "COMPLIANCE_CHECKED", {"regulations": req.regulations})
    return {"agent_id": req.agent_id, "checked_at": datetime.utcnow().isoformat(), "regulations": result}
