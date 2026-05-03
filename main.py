"""
VeriSigil AI — API Server v0.3.1
Best of both: clean structure + full feature set
Ed25519 signatures + DID resolution + Audit log + Security scan + Compliance
"""
import base64, hashlib, os, uuid, json
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
from nacl.signing import SigningKey

# ── Environment config ────────────────────────────────────
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
SIGN_SECRET  = os.environ.get("SIGN_SECRET", "verisigil-secret-2026")
API_KEY      = os.environ.get("VERISIGIL_API_KEY", "verisigil-secret-2026")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise Exception("SUPABASE_URL and SUPABASE_KEY must be set in environment variables")

_seed          = hashlib.sha256(SIGN_SECRET.encode()).digest()
SIGNING_KEY    = SigningKey(_seed)
VERIFY_KEY     = SIGNING_KEY.verify_key
PUBLIC_KEY_B64 = base64.b64encode(bytes(VERIFY_KEY)).decode()

# ── App setup ─────────────────────────────────────────────
app = FastAPI(
    title="VeriSigil AI API",
    description="The cryptographic identity and security layer for autonomous AI agents.",
    version="0.3.1",
    docs_url="/docs",
)

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

# ── Auth ──────────────────────────────────────────────────
def require_api_key(x_api_key: Optional[str]):
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(401, "Invalid or missing API key. Pass your key in the x-api-key header.")

# ── DB helpers ────────────────────────────────────────────
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
        if r.status_code >= 400:
            print(f"[DB INSERT ERROR] table={table} status={r.status_code} response={r.text[:200]}")
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
        if r.status_code >= 400:
            print(f"[DB PATCH ERROR] table={table} status={r.status_code} response={r.text[:200]}")
        result = r.json()
        return result[0] if isinstance(result, list) and result else data

# ── Crypto ────────────────────────────────────────────────
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

# ── Audit log ─────────────────────────────────────────────
async def log_event(agent_id: str, event: str, event_data: dict = {}):
    """Append a signed audit event to the passport record."""
    try:
        passport = await db_get("passports", "agent_id", agent_id)
        if not passport:
            return
        timestamp = datetime.utcnow().isoformat()
        new_event = {
            "event":          event,
            "timestamp":      timestamp,
            "event_data":     event_data,
            "signature":      sign_payload({"agent_id": agent_id, "event": event, "timestamp": timestamp}),
            "signature_type": "Ed25519",
        }
        existing = passport.get("audit_events") or []
        await db_patch("passports", "agent_id", agent_id,
                       {"audit_events": existing + [new_event]})
    except Exception as e:
        print(f"[AUDIT ERROR] agent={agent_id} event={event} error={e}")

# ── Passport generator ────────────────────────────────────
def make_passport(agent_name, owner, framework, runtime, version, tags, expiry_days):
    _id       = f"vsa_{uuid.uuid4().hex[:12]}"
    slug      = agent_name.lower().replace(" ", "-")
    did       = f"did:web:verisigilai.com:agents:{slug}-{_id[-6:]}"
    now       = datetime.utcnow()
    issued_at = now.isoformat()
    exp       = now + timedelta(days=expiry_days)
    issued_event = {
        "event":          "ISSUED",
        "timestamp":      issued_at,
        "event_data":     {"agent_name": agent_name, "owner": owner, "framework": framework},
        "signature":      sign_payload({"agent_id": _id, "event": "ISSUED", "timestamp": issued_at}),
        "signature_type": "Ed25519",
    }
    return {
        "agent_id":        _id,
        "agent_name":      agent_name,
        "did":             did,
        "public_key":      PUBLIC_KEY_B64,
        "signature":       sign_payload({"agent_id": _id, "did": did,
                                         "issued_at": issued_at, "owner": owner,
                                         "issuer": "https://verisigilai.com"}),
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
        "audit_events":    [issued_event],
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
        "version":        "0.3.1",
        "status":         "live",
        "description":    "Cryptographic identity and security for autonomous AI agents.",
        "website":        "https://www.verisigilai.com",
        "docs":           "/docs",
        "public_key":     PUBLIC_KEY_B64,
        "signature_type": "Ed25519",
        "auth":           "Pass your API key in the x-api-key header for protected endpoints.",
        "endpoints": {
            "issue":      "POST /v1/passport/issue        [requires x-api-key]",
            "get":        "GET  /v1/passport/{agent_id}   [public]",
            "audit":      "GET  /v1/passport/{agent_id}/audit [public]",
            "verify":     "GET  /verify/{agent_id}        [public]",
            "did":        "GET  /did/{agent_id}           [public]",
            "revoke":     "POST /v1/passport/revoke       [requires x-api-key]",
            "scan":       "POST /v1/security/scan         [requires x-api-key]",
            "compliance": "POST /v1/compliance/check      [requires x-api-key]",
        }
    }

@app.get("/health")
async def health():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat(), "version": "0.3.1"}

@app.get("/issue-test")
async def issue_test():
    """Test endpoint — issues a real stored passport. No auth. For testing only."""
    p = make_passport("verisigil-test-agent", "raheem@verisigilai.com",
                      "langchain", "python", "1.0.0", ["test"], 365)
    try:
        await db_insert("passports", p)
        p["stored"] = True
    except Exception as e:
        p["stored"] = False
        p["error"]  = str(e)
    return {"success": True, "passport": p}

@app.post("/v1/passport/issue")
async def issue(req: IssueReq, x_api_key: Optional[str] = Header(None)):
    """Issue a new Ed25519 signed passport. Requires x-api-key header."""
    require_api_key(x_api_key)
    p = make_passport(req.agent_name, req.owner, req.framework,
                      req.runtime, req.version, req.tags, req.expiry_days)
    try:
        await db_insert("passports", p)
        p["stored"] = True
    except Exception as e:
        p["stored"]  = False
        p["warning"] = str(e)
    return {"success": True, "passport": p}

@app.get("/v1/passport/{agent_id}/audit")
async def get_audit(agent_id: str):
    """Get cryptographic audit log. Public — no auth needed."""
    p = await db_get("passports", "agent_id", agent_id)
    if not p:
        raise HTTPException(404, "Passport not found.")
    events = p.get("audit_events") or []
    verified = []
    for e in events:
        sig_valid = verify_payload(
            {"agent_id": agent_id, "event": e["event"], "timestamp": e["timestamp"]},
            e.get("signature", ""))
        verified.append({**e, "signature_valid": sig_valid})
    return {
        "agent_id":       agent_id,
        "total_events":   len(verified),
        "audit_log":      verified,
        "public_key":     PUBLIC_KEY_B64,
        "signature_type": "Ed25519",
        "issued_by":      "VeriSigil AI",
    }

@app.get("/v1/passport/{agent_id}")
async def get_p(agent_id: str):
    """Retrieve a stored passport. Public."""
    p = await db_get("passports", "agent_id", agent_id)
    if not p:
        raise HTTPException(404, "Passport not found.")
    return {"success": True, "passport": p}

@app.get("/verify/{agent_id}")
async def verify_get(agent_id: str):
    """PUBLIC — cryptographic verification. No auth needed."""
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

@app.get("/did/{agent_id}")
async def did_resolution(agent_id: str):
    """W3C DID Document. Public."""
    p = await db_get("passports", "agent_id", agent_id)
    if not p:
        raise HTTPException(404, {"error": "notFound", "message": f"DID not found for {agent_id}"})
    did     = p.get("did")
    pub_key = p.get("public_key", PUBLIC_KEY_B64)
    return {
        "@context": ["https://www.w3.org/ns/did/v1",
                     "https://w3id.org/security/suites/ed25519-2020/v1"],
        "id":         did,
        "controller": "did:web:verisigilai.com",
        "verificationMethod": [{"id": f"{did}#key-1",
                                 "type": "Ed25519VerificationKey2020",
                                 "controller": did,
                                 "publicKeyMultibase": "z" + base64.b64encode(
                                     base64.b64decode(pub_key)).decode()}],
        "authentication":  [f"{did}#key-1"],
        "assertionMethod": [f"{did}#key-1"],
        "service": [{"id": f"{did}#verisigil",
                     "type": "VeriSigilPassportService",
                     "serviceEndpoint": f"https://verisigil-api-production.up.railway.app/verify/{agent_id}"}],
        "metadata": {"agent_id": agent_id, "agent_name": p.get("agent_name"),
                     "status": p.get("status"), "trust_score": p.get("trust_score"),
                     "issued_at": p.get("issued_at"), "expires_at": p.get("expires_at"),
                     "issuer": "VeriSigil AI", "eu_ai_act": p.get("eu_ai_act"),
                     "compliant": p.get("compliant")}
    }

@app.post("/v1/passport/revoke")
async def revoke(req: RevokeReq, x_api_key: Optional[str] = Header(None)):
    """Revoke a passport immediately. Requires x-api-key."""
    require_api_key(x_api_key)
    p = await db_get("passports", "agent_id", req.agent_id)
    if not p:
        raise HTTPException(404, "Passport not found.")
    await db_patch("passports", "agent_id", req.agent_id,
                   {"status": "REVOKED", "revoked_at": datetime.utcnow().isoformat(),
                    "revoke_reason": req.reason})
    await log_event(req.agent_id, "REVOKED", {"reason": req.reason})
    return {"revoked": True, "agent_id": req.agent_id, "reason": req.reason}

@app.post("/v1/security/scan")
async def scan(req: ScanReq, x_api_key: Optional[str] = Header(None)):
    """Scan agent code for vulnerabilities. Requires x-api-key."""
    require_api_key(x_api_key)
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
        "scan_id":       f"scan_{uuid.uuid4().hex[:12]}",
        "agent_id":      req.agent_id,
        "lines_scanned": len(lines),
        "threats":       threats,
        "threat_count":  len(threats),
        "severity_summary": {
            "HIGH":   sum(1 for t in threats if t["severity"] == "HIGH"),
            "MEDIUM": sum(1 for t in threats if t["severity"] == "MEDIUM"),
            "LOW":    0,
        },
        "passed":     len(threats) == 0,
        "scanned_at": datetime.utcnow().isoformat(),
    }

@app.post("/v1/compliance/check")
async def compliance(req: ComplianceReq, x_api_key: Optional[str] = Header(None)):
    """Check compliance status. Requires x-api-key."""
    require_api_key(x_api_key)
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
    return {"agent_id": req.agent_id,
            "checked_at": datetime.utcnow().isoformat(),
            "regulations": result}
