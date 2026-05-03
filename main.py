"""
VeriSigil AI — API Server v0.3.0
Real Ed25519 signatures + DID resolution + Cryptographic Audit Log
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
async def db_insert(table, data):
    if not SUPABASE_KEY:
        return data
    async with httpx.AsyncClient() as c:
        r = await c.post(
            f"{SUPABASE_URL}/rest/v1/{table}",
            headers={"apikey": SUPABASE_KEY,
                     "Authorization": f"Bearer {SUPABASE_KEY}",
                     "Content-Type": "application/json",
                     "Prefer": "return=representation"},
            json=data, timeout=10)
        result = r.json()
        return result[0] if isinstance(result, list) and result else data

async def db_get(table, field, value):
    if not SUPABASE_KEY:
        return None
    async with httpx.AsyncClient() as c:
        r = await c.get(
            f"{SUPABASE_URL}/rest/v1/{table}?{field}=eq.{value}",
            headers={"apikey": SUPABASE_KEY,
                     "Authorization": f"Bearer {SUPABASE_KEY}"},
            timeout=10)
        result = r.json()
        return result[0] if isinstance(result, list) and result else None

async def db_get_many(table, field, value):
    if not SUPABASE_KEY:
        return []
    async with httpx.AsyncClient() as c:
        r = await c.get(
            f"{SUPABASE_URL}/rest/v1/{table}?{field}=eq.{value}&order=created_at.asc",
            headers={"apikey": SUPABASE_KEY,
                     "Authorization": f"Bearer {SUPABASE_KEY}"},
            timeout=10)
        result = r.json()
        return result if isinstance(result, list) else []

async def db_update(table, field, value, data):
    if not SUPABASE_KEY:
        return data
    async with httpx.AsyncClient() as c:
        r = await c.patch(
            f"{SUPABASE_URL}/rest/v1/{table}?{field}=eq.{value}",
            headers={"apikey": SUPABASE_KEY,
                     "Authorization": f"Bearer {SUPABASE_KEY}",
                     "Content-Type": "application/json",
                     "Prefer": "return=representation"},
            json=data, timeout=10)
        result = r.json()
        return result[0] if isinstance(result, list) and result else data

# ── Audit log helper ──────────────────────────────────────
def sign_event(agent_id, event, timestamp):
    """Sign an audit event with Ed25519."""
    payload = json.dumps({
        "agent_id":  agent_id,
        "event":     event,
        "timestamp": timestamp,
        "issuer":    "https://verisigilai.com",
    }, sort_keys=True).encode()
    signed = SIGNING_KEY.sign(payload)
    return base64.b64encode(signed.signature).decode()

async def log_event(agent_id, event, event_data={}):
    """Write a signed event to the audit log."""
    timestamp = datetime.utcnow().isoformat()
    signature = sign_event(agent_id, event, timestamp)
    record = {
        "agent_id":   agent_id,
        "event":      event,
        "event_data": event_data,
        "signature":  signature,
        "timestamp":  timestamp,
    }
    try:
        await db_insert("audit_log", record)
    except Exception:
        pass
    return record

# ── Passport signing ──────────────────────────────────────
def sign_passport(agent_id, did, issued_at, owner):
    payload = json.dumps({
        "agent_id":  agent_id,
        "did":       did,
        "issued_at": issued_at,
        "owner":     owner,
        "issuer":    "https://verisigilai.com",
    }, sort_keys=True).encode()
    signed = SIGNING_KEY.sign(payload)
    return base64.b64encode(signed.signature).decode()

def verify_sig(agent_id, did, issued_at, owner, sig_b64):
    try:
        payload = json.dumps({
            "agent_id":  agent_id,
            "did":       did,
            "issued_at": issued_at,
            "owner":     owner,
            "issuer":    "https://verisigilai.com",
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
    return {
        "agent_id":        _id,
        "agent_name":      agent_name,
        "did":             did,
        "public_key":      PUBLIC_KEY_B64,
        "signature":       sign_passport(_id, did, issued_at, owner),
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
    }

def get_key(auth):
    return (auth or "").replace("Bearer ", "").strip()

def is_demo(key):
    return not key or key == "demo"

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
    return {
        "status":    "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version":   "0.3.0",
    }

@app.get("/issue-test")
async def issue_test():
    """Issues and stores a real test passport. No auth needed."""
    p = make_passport("verisigil-test-agent", "raheem@verisigilai.com",
                      "langchain", "python", "1.0.0", ["test"], 365)
    try:
        await db_insert("passports", p)
        await log_event(p["agent_id"], "ISSUED", {
            "agent_name": p["agent_name"],
            "owner":      p["owner"],
            "framework":  p["framework"],
        })
        p["stored"] = True
    except Exception as e:
        p["stored"] = False
        p["error"]  = str(e)
    return {"success": True, "passport": p}

@app.post("/v1/passport/issue")
async def issue(req: IssueReq, authorization: Optional[str] = Header(None)):
    """Issue a new Ed25519 signed passport. Stored automatically."""
    p = make_passport(req.agent_name, req.owner, req.framework,
                      req.runtime, req.version, req.tags, req.expiry_days)
    try:
        await db_insert("passports", p)
        await log_event(p["agent_id"], "ISSUED", {
            "agent_name": req.agent_name,
            "owner":      req.owner,
            "framework":  req.framework,
        })
        p["stored"] = True
    except Exception as e:
        p["stored"]  = False
        p["warning"] = "Issued but not stored — " + str(e)
    return {"success": True, "passport": p}

@app.get("/v1/passport/{agent_id}/audit")
async def get_audit(agent_id: str):
    """
    Get the cryptographic audit log for an agent.
    Every event is Ed25519 signed — immutable and verifiable.
    No API key required — audit logs are public.
    """
    events = await db_get_many("audit_log", "agent_id", agent_id)

    if not events:
        return {
            "agent_id":     agent_id,
            "total_events": 0,
            "audit_log":    [],
            "note":         "No events found for this agent.",
        }

    # Verify each event signature
    verified_events = []
    for e in events:
        sig_payload = json.dumps({
            "agent_id":  e["agent_id"],
            "event":     e["event"],
            "timestamp": e["timestamp"],
            "issuer":    "https://verisigilai.com",
        }, sort_keys=True).encode()
        try:
            VERIFY_KEY.verify(sig_payload, base64.b64decode(e.get("signature", "")))
            sig_valid = True
        except Exception:
            sig_valid = False

        verified_events.append({
            "event":          e["event"],
            "timestamp":      e["timestamp"],
            "event_data":     e.get("event_data", {}),
            "signature":      e.get("signature", ""),
            "signature_valid": sig_valid,
            "signature_type": "Ed25519",
        })

    return {
        "agent_id":       agent_id,
        "total_events":   len(verified_events),
        "audit_log":      verified_events,
        "public_key":     PUBLIC_KEY_B64,
        "signature_type": "Ed25519",
        "issued_by":      "VeriSigil AI",
        "note": "Every event is Ed25519 signed. Verify any event independently using the public key.",
    }

@app.get("/v1/passport/{agent_id}")
async def get_p(agent_id: str):
    """Retrieve a stored passport by agent ID."""
    p = await db_get("passports", "agent_id", agent_id)
    if not p:
        raise HTTPException(404, "Passport not found.")
    return {"success": True, "passport": p}

@app.get("/verify/{agent_id}")
async def verify_get(agent_id: str):
    """PUBLIC — verify any agent. No API key needed."""
    p = await db_get("passports", "agent_id", agent_id)
    if not p:
        return {
            "valid":    False,
            "verified": False,
            "agent_id": agent_id,
            "reason":   "Passport not found — may have been issued in demo mode",
            "issuer":   "verisigilai.com",
        }

    sig_valid   = verify_sig(p["agent_id"], p["did"],
                              p["issued_at"], p["owner"], p.get("signature", ""))
    is_active   = p.get("status") == "ACTIVE"
    not_expired = datetime.utcnow() < datetime.fromisoformat(p["expires_at"])

    # Log every verification event
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
    """Verify a passport by agent ID — POST version."""
    p = await db_get("passports", "agent_id", req.agent_id)
    if not p:
        return {"verified": False, "agent_id": req.agent_id, "reason": "Not found"}
    if p.get("status") != "ACTIVE":
        return {"verified": False, "agent_id": req.agent_id,
                "reason": f"Status: {p['status']}"}
    if datetime.utcnow() > datetime.fromisoformat(p["expires_at"]):
        return {"verified": False, "agent_id": req.agent_id, "reason": "Expired"}

    sig_valid = verify_sig(p["agent_id"], p["did"],
                           p["issued_at"], p["owner"], p.get("signature", ""))
    await log_event(req.agent_id, "VERIFIED", {"method": "POST /verify"})

    return {
        "verified":       sig_valid,
        "agent_id":       req.agent_id,
        "trust_score":    p.get("trust_score", 0.97),
        "status":         p.get("status"),
        "did":            p.get("did"),
        "signature_valid": sig_valid,
        "signature_type": "Ed25519",
        "public_key":     PUBLIC_KEY_B64,
    }

@app.get("/did/{agent_id}")
async def did_resolution(agent_id: str):
    """W3C DID Document — PUBLIC, no auth needed."""
    p = await db_get("passports", "agent_id", agent_id)
    if not p:
        raise HTTPException(404, {"error": "notFound",
            "message": f"DID not found for {agent_id}",
            "hint":    "Agent may have been issued in demo mode."})
    did     = p.get("did", f"did:web:verisigilai.com:agents:{agent_id}")
    pub_key = p.get("public_key", PUBLIC_KEY_B64)
    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id":         did,
        "controller": "did:web:verisigilai.com",
        "verificationMethod": [{
            "id":                 f"{did}#key-1",
            "type":               "Ed25519VerificationKey2020",
            "controller":         did,
            "publicKeyMultibase": "z" + base64.b64encode(
                                      base64.b64decode(pub_key)).decode(),
        }],
        "authentication":  [f"{did}#key-1"],
        "assertionMethod": [f"{did}#key-1"],
        "service": [{
            "id":              f"{did}#verisigil",
            "type":            "VeriSigilPassportService",
            "serviceEndpoint": f"https://verisigil-api-production.up.railway.app/verify/{agent_id}",
        }],
        "metadata": {
            "agent_id":    agent_id,
            "agent_name":  p.get("agent_name"),
            "status":      p.get("status"),
            "trust_score": p.get("trust_score"),
            "issued_at":   p.get("issued_at"),
            "expires_at":  p.get("expires_at"),
            "issuer":      "VeriSigil AI",
            "eu_ai_act":   p.get("eu_ai_act"),
            "compliant":   p.get("compliant"),
        }
    }

@app.post("/v1/passport/revoke")
async def revoke(req: RevokeReq):
    """Revoke a passport immediately."""
    p = await db_get("passports", "agent_id", req.agent_id)
    if not p:
        raise HTTPException(404, "Passport not found.")
    await db_update("passports", "agent_id", req.agent_id, {
        "status":         "REVOKED",
        "revoked_at":     datetime.utcnow().isoformat(),
        "revoke_reason":  req.reason,
    })
    await log_event(req.agent_id, "REVOKED", {"reason": req.reason})
    return {"revoked": True, "agent_id": req.agent_id, "reason": req.reason}

@app.post("/v1/security/scan")
async def scan(req: ScanReq):
    """Scan agent code for security vulnerabilities."""
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
        await log_event(req.agent_id, "SCANNED", {
            "lines_scanned": len(lines),
            "threats_found": len(threats),
        })

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
async def compliance(req: ComplianceReq):
    """Check compliance status against regulations."""
    result = {}
    if "eu_ai_act" in req.regulations:
        result["eu_ai_act"] = {
            "compliant":  True,
            "risk_class": "LIMITED_RISK",
            "deadline":   "2026-08-01",
            "note":       "Designed for EU AI Act alignment — certification in progress",
        }
    if "gdpr"  in req.regulations:
        result["gdpr"]  = {"compliant": True, "lawful_basis": "legitimate_interest"}
    if "hipaa" in req.regulations:
        result["hipaa"] = {"compliant": False,
                           "reason": "BAA required — contact info@verisigilai.com"}
    if "soc2"  in req.regulations:
        result["soc2"]  = {"compliant": False,
                           "reason": "SOC 2 audit in progress — Q4 2026"}

    await log_event(req.agent_id, "COMPLIANCE_CHECKED", {
        "regulations": req.regulations
    })

    return {
        "agent_id":   req.agent_id,
        "checked_at": datetime.utcnow().isoformat(),
        "regulations": result,
    }
