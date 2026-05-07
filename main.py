"""
VeriSigil AI — API Server v0.3.1
Best of both: clean structure + full feature set
Ed25519 signatures + DID resolution + Audit log + Security scan + Compliance
"""
import base64, hashlib, math, os, uuid, json
from time import time
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
from nacl.signing import SigningKey

# ── Environment config ────────────────────────────────────
SUPABASE_URL         = os.environ.get("SUPABASE_URL")
SUPABASE_KEY         = os.environ.get("SUPABASE_KEY")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", os.environ.get("SUPABASE_KEY"))
SIGN_SECRET          = os.environ.get("SIGN_SECRET", "verisigil-secret-2026")
API_KEY              = os.environ.get("VERISIGIL_API_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise Exception("SUPABASE_URL and SUPABASE_KEY must be set in environment variables")
if not API_KEY:
    raise Exception("VERISIGIL_API_KEY must be set in environment variables")

_seed          = hashlib.sha256(SIGN_SECRET.encode()).digest()
SIGNING_KEY    = SigningKey(_seed)
VERIFY_KEY     = SIGNING_KEY.verify_key
PUBLIC_KEY_B64 = base64.b64encode(bytes(VERIFY_KEY)).decode()


# ── Rate limiter ──────────────────────────────────────────
RATE_LIMIT_STORE: dict = {}
MAX_REQUESTS_PER_MINUTE = 10

def check_rate_limit(client_ip: str) -> bool:
    """Allow max 10 verify calls per IP per minute."""
    now    = time()
    window = RATE_LIMIT_STORE.get(client_ip, [])
    window = [t for t in window if now - t < 60]
    if len(window) >= MAX_REQUESTS_PER_MINUTE:
        return False
    window.append(now)
    RATE_LIMIT_STORE[client_ip] = window
    return True

# ── App setup ─────────────────────────────────────────────
app = FastAPI(
    title="VeriSigil AI API",
    description="The cryptographic identity and security layer for autonomous AI agents.",
    version="0.4.0",
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
def get_headers(write=False):
    key = SUPABASE_SERVICE_KEY if write else SUPABASE_KEY
    return {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }

async def db_insert(table, data):
    async with httpx.AsyncClient() as c:
        r = await c.post(f"{SUPABASE_URL}/rest/v1/{table}",
                         headers=get_headers(write=True), json=data, timeout=10)
        if r.status_code >= 400:
            print(f"[DB INSERT ERROR] table={table} status={r.status_code} response={r.text[:200]}")
            return {"code": r.status_code, "message": r.text[:200]}
        result = r.json()
        return result[0] if isinstance(result, list) and result else data

async def db_get(table, field, value):
    async with httpx.AsyncClient() as c:
        r = await c.get(f"{SUPABASE_URL}/rest/v1/{table}?{field}=eq.{value}",
                        headers=get_headers(write=False), timeout=10)
        result = r.json()
        return result[0] if isinstance(result, list) and result else None

async def db_patch(table, field, value, data):
    async with httpx.AsyncClient() as c:
        r = await c.patch(f"{SUPABASE_URL}/rest/v1/{table}?{field}=eq.{value}",
                          headers=get_headers(write=True), json=data, timeout=10)
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



async def get_verifier(api_key: str) -> dict:
    """Look up verifier by API key. Returns None if not found."""
    if not api_key or api_key == "demo":
        return {
            "id":         "ver_public",
            "name":       "Public",
            "type":       "public",
            "reputation": 0.3,
        }
    verifier = await db_get("verifiers", "api_key", api_key)
    return verifier

async def update_verifier_reputation(verifier_id: str, action: str = "verify"):
    """Update verifier reputation after a verification."""
    verifier = await db_get("verifiers", "id", verifier_id)
    if not verifier:
        return
    rep = verifier.get("reputation", 0.5)
    if action == "verify":
        rep += 0.01
    elif action == "flag":
        rep -= 0.05
    rep = max(0.1, min(1.0, round(rep, 4)))
    count = (verifier.get("verifications") or 0) + 1
    await db_patch("verifiers", "id", verifier_id, {
        "reputation":     rep,
        "verifications":  count,
    })

# ── Dynamic trust score ───────────────────────────────────
def calculate_trust_score(issued_at: str, verification_count: int,
                           high_threats: int, medium_threats: int,
                           unique_verifiers: int = 0,
                           avg_verifier_reputation: float = 0.5) -> float:
    """
    Dynamic trust score v2 — network-aware, anti-gaming.
    Capped boost at +0.02 regardless of verification count.
    """
    try:
        now    = datetime.utcnow()
        issued = datetime.fromisoformat(issued_at)
        days   = max(0, (now - issued).days)
    except Exception:
        days = 0

    score = 0.97
    score -= 0.001 * days
    score -= 0.15  * (high_threats or 0)
    score -= 0.05  * (medium_threats or 0)

    effective = max(unique_verifiers or 0, verification_count or 0)
    rep       = float(avg_verifier_reputation or 0.5)
    boost     = rep * 0.005 * math.log(effective + 1)
    score    += min(boost, 0.02)

    return max(0.0, min(1.0, round(score, 4)))

def trust_level(score: float) -> str:
    """Convert trust score to human-readable level."""
    if score >= 0.80: return "TRUSTED"
    if score >= 0.60: return "FLAGGED"
    return "BLOCKED"

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
        existing = list(passport.get("audit_events") or [])
        existing.append(new_event)
        await db_patch("passports", "agent_id", agent_id,
                       {"audit_events": existing})
    except Exception as e:
        print(f"[AUDIT ERROR] agent={agent_id} event={event} error={e}")

# ── Passport generator ────────────────────────────────────
def make_passport(agent_name, owner, framework, runtime, version, tags, expiry_days,
                  display_name=None, issuer_org=None):
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
        # Agent Name Layer
        "display_name":    display_name or agent_name,
        "issuer_org":      issuer_org or owner,
        "verification_tier": 0,
        "tier_label":      "Self-Declared",
        "tier_color":      "#888888",
        "is_protected":    agent_name.lower() in PROTECTED_NAMES,
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
# Protected names that require org verification
PROTECTED_NAMES = {
    "chatgpt", "gpt-4", "gpt-4o", "gpt4", "claude", "grok",
    "gemini", "copilot", "llama", "perplexity", "mistral"
}

TIER_LABELS = {
    0: "Self-Declared",
    1: "Domain-Verified",
    2: "Org-Verified",
    3: "Certified"
}

TIER_BADGE_COLORS = {
    0: "#888888",  # grey
    1: "#4FC3F7",  # light blue
    2: "#00D4F5",  # cyan
    3: "#FFD700"   # gold
}

class IssueReq(BaseModel):
    agent_name:   str
    owner:        str
    framework:    str = "unknown"
    runtime:      str = "python"
    version:      str = "1.0.0"
    tags:         List[str] = []
    expiry_days:  int = 365
    # NEW: Agent Name Layer fields
    display_name: Optional[str] = None   # human-readable name e.g. "FinanceGuard-7"
    issuer_org:   Optional[str] = None   # organization name e.g. "FinTech Corp"

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
        "version":        "0.4.0",
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
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat(), "version": "0.4.4"}

@app.get("/issue-test")
async def issue_test():
    """Test endpoint — issues a real stored passport. No auth. For testing only."""
    p = make_passport("verisigil-test-agent", "raheem@verisigilai.com",
                      "langchain", "python", "1.0.0", ["test"], 365)
    db_record = {k: p[k] for k in [
        "agent_id","agent_name","did","public_key","signature",
        "signature_type","owner","issuer","status","trust_score",
        "eu_risk_class","compliant","framework","runtime","version",
        "tags","display_name","issuer_org","verification_tier",
        "tier_label","issued_at","expires_at","eu_ai_act","gdpr","hipaa","soc2"
    ] if k in p}
    db_record["is_protected_name"] = p.get("is_protected", False)
    try:
        await db_insert("passports", db_record)
        p["stored"] = True
    except Exception as e:
        p["stored"] = False
        p["error"]  = str(e)
    return {"success": True, "passport": p}

@app.post("/v1/passport/issue")
async def issue(req: IssueReq, x_api_key: Optional[str] = Header(None)):
    """Issue a new Ed25519 signed passport. Requires x-api-key header."""
    require_api_key(x_api_key)

    # Check if requested display_name is a protected name
    check_name = (req.display_name or req.agent_name).lower().strip()
    if check_name in PROTECTED_NAMES:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "PROTECTED_NAME",
                "message": f"'{req.display_name or req.agent_name}' is a reserved name. "
                           "Contact verify@verisigilai.com for org-verified registration.",
                "protected_names": "ChatGPT, Grok, Claude, Gemini, Copilot, Llama, Perplexity, Mistral"
            }
        )

    p = make_passport(
        req.agent_name, req.owner, req.framework,
        req.runtime, req.version, req.tags, req.expiry_days,
        display_name=req.display_name,
        issuer_org=req.issuer_org
    )
    # Strip fields that don't exist in Supabase — only insert DB columns
    db_record = {
        "agent_id":          p["agent_id"],
        "agent_name":        p["agent_name"],
        "did":               p["did"],
        "public_key":        p["public_key"],
        "signature":         p["signature"],
        "signature_type":    p["signature_type"],
        "owner":             p["owner"],
        "issuer":            p["issuer"],
        "status":            p["status"],
        "trust_score":       p["trust_score"],
        "eu_risk_class":     p["eu_risk_class"],
        "compliant":         p["compliant"],
        "framework":         p["framework"],
        "runtime":           p["runtime"],
        "version":           p["version"],
        "tags":              p["tags"],
        "display_name":      p["display_name"],
        "issuer_org":        p["issuer_org"],
        "verification_tier": p["verification_tier"],
        "tier_label":        p["tier_label"],
        "is_protected_name": p["is_protected"],
        "issued_at":         p["issued_at"],
        "expires_at":        p["expires_at"],
        "eu_ai_act":         p["eu_ai_act"],
        "gdpr":              p["gdpr"],
        "hipaa":             p["hipaa"],
        "soc2":              p["soc2"],
    }
    try:
        result = await db_insert("passports", db_record)
        # Check Supabase didn't return an error object
        if isinstance(result, dict) and result.get("code"):
            p["stored"]   = False
            p["db_error"] = result.get("message", "DB insert rejected")
        else:
            p["stored"] = True
    except Exception as e:
        p["stored"]   = False
        p["db_error"] = str(e)
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
async def verify_get(agent_id: str, request: Request,
                     x_api_key: Optional[str] = Header(None)):
    """PUBLIC — cryptographic verification. Rate limited to 10/min per IP."""
    try:
        # Rate limit check
        client_ip = request.client.host if request.client else "unknown"
        if not check_rate_limit(client_ip):
            raise HTTPException(429, "Too many requests — max 10/min per IP.")

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

        # Get verifier — safe fallback
        try:
            verifier = await get_verifier(x_api_key)
        except Exception:
            verifier = {"id": "ver_public", "type": "public", "reputation": 0.3}

        verifier_id  = verifier.get("id", "ver_public")
        verifier_rep = float(verifier.get("reputation", 0.3))

        # Compute unique verifiers from audit log
        existing_events = p.get("audit_events") or []
        all_verifier_ids = [
            e.get("event_data", {}).get("verifier_id")
            for e in existing_events
            if e.get("event") == "VERIFIED"
        ] + [verifier_id]
        unique_verifier_count = len(set(v for v in all_verifier_ids if v))

        # Check duplicate
        recent_ids = [
            e.get("event_data", {}).get("verifier_id")
            for e in existing_events[-5:]
            if e.get("event") == "VERIFIED"
        ]
        is_duplicate = verifier_id in recent_ids

        # New count and score
        new_count = (p.get("verification_count") or 0) + 1
        new_score = calculate_trust_score(
            p["issued_at"], new_count,
            p.get("high_threats") or 0,
            p.get("medium_threats") or 0,
            unique_verifiers=unique_verifier_count,
            avg_verifier_reputation=verifier_rep,
        )

        # Update DB — non-blocking
        if not is_duplicate:
            try:
                await db_patch("passports", "agent_id", agent_id, {
                    "verification_count": new_count,
                    "trust_score":        new_score,
                })
            except Exception as e:
                print(f"[VERIFY PATCH ERROR] {e}")

        # Log event — non-blocking
        try:
            await log_event(agent_id, "VERIFIED", {
                "method":              "GET /verify",
                "verifier_id":         verifier_id,
                "verifier_type":       verifier.get("type", "public"),
                "verifier_reputation": verifier_rep,
                "verification_count":  new_count,
                "unique_verifiers":    unique_verifier_count,
                "trust_score":         new_score,
                "trust_level":         trust_level(new_score),
                "duplicate":           is_duplicate,
            })
        except Exception as e:
            print(f"[VERIFY LOG ERROR] {e}")

        return {
            "valid":              sig_valid and is_active and not_expired,
            "verified":           sig_valid,
            "agent_id":           agent_id,
            "did":                p.get("did"),
            "status":             p.get("status"),
            "trust_score":        new_score,
            "trust_level":        trust_level(new_score),
            "verification_count": new_count,
            "unique_verifiers":   unique_verifier_count,
            "signature_valid":    sig_valid,
            "signature_type":     "Ed25519",
            "public_key":         PUBLIC_KEY_B64,
            "issuer":             "verisigilai.com",
            "issued_at":          p.get("issued_at"),
            "expires_at":         p.get("expires_at"),
            "compliant":          p.get("compliant"),
            "eu_ai_act":          p.get("eu_ai_act"),
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"[VERIFY ERROR] agent={agent_id} error={e}")
        raise HTTPException(500, f"Verification error: {str(e)}")

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


@app.get("/v1/trust/{agent_id}/graph")
async def trust_graph(agent_id: str):
    """
    Trust graph — shows who has verified this agent and their reputation.
    Public endpoint. Visualises the trust network around an agent.
    """
    p = await db_get("passports", "agent_id", agent_id)
    if not p:
        raise HTTPException(404, "Passport not found.")

    events = p.get("audit_events") or []
    nodes, edges = [], []
    seen_verifiers = set()

    for e in events:
        if e.get("event") != "VERIFIED":
            continue
        v_id  = e.get("event_data", {}).get("verifier_id", "ver_public")
        v_rep = e.get("event_data", {}).get("verifier_reputation", 0.3)
        v_type = e.get("event_data", {}).get("verifier_type", "public")
        ts    = e.get("timestamp", "")

        if v_id not in seen_verifiers:
            nodes.append({
                "id":         v_id,
                "type":       "verifier",
                "verifier_type": v_type,
                "reputation": v_rep,
                "label":      v_id,
            })
            seen_verifiers.add(v_id)

        edges.append({
            "from":      v_id,
            "to":        agent_id,
            "type":      "verified",
            "timestamp": ts,
        })

    nodes.append({
        "id":          agent_id,
        "type":        "agent",
        "trust_score": p.get("trust_score", 0.97),
        "trust_level": trust_level(p.get("trust_score", 0.97)),
        "label":       agent_id,
    })

    return {
        "agent_id":        agent_id,
        "trust_score":     p.get("trust_score", 0.97),
        "trust_level":     trust_level(p.get("trust_score", 0.97)),
        "unique_verifiers": len(seen_verifiers),
        "total_verifications": len(edges),
        "nodes":           nodes,
        "edges":           edges,
        "note": "Visualise at: verisigil-api-production.up.railway.app/v1/trust/{agent_id}/graph",
    }

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
        high_count   = sum(1 for t in threats if t["severity"] == "HIGH")
        medium_count = sum(1 for t in threats if t["severity"] == "MEDIUM")

        # Update threat counts and recalculate trust score
        passport = await db_get("passports", "agent_id", req.agent_id)
        if passport:
            new_high   = (passport.get("high_threats")   or 0) + high_count
            new_medium = (passport.get("medium_threats") or 0) + medium_count
            new_score  = calculate_trust_score(
                passport["issued_at"],
                passport.get("verification_count", 0),
                new_high,
                new_medium,
                unique_verifiers=0,
                avg_verifier_reputation=0.5,
            )
            await db_patch("passports", "agent_id", req.agent_id, {
                "high_threats":   new_high,
                "medium_threats": new_medium,
                "trust_score":    new_score,
            })

        await log_event(req.agent_id, "SCANNED", {
            "lines_scanned":  len(lines),
            "threats_found":  len(threats),
            "high_threats":   high_count,
            "medium_threats": medium_count,
            "new_trust_score": new_score if passport else None,
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
    # ─────────────────────────────────────────────────────────
# VeriSigil v0.4.5 — POST /v1/action/evaluate
# ─────────────────────────────────────────────────────────

class ActionEvaluateRequest(BaseModel):
    agent_id:    str
    action_type: str
    risk_level:  str  # "low", "medium", or "critical"
    context:     Optional[str] = "production"

class ActionEvaluateResponse(BaseModel):
    decision:                     str
    decision_confidence:          float
    reason:                       str
    trust_score:                  float
    shadow_detected:              bool
    eu_risk_class:                str
    article_14_oversight_required: bool
    suggested_policy:             str
    evaluation_id:                str
    evaluated_at:                 str

def compute_action_decision(trust_score, shadow_detected, eu_risk_class, risk_level, action_type, context):
    article_14_required = eu_risk_class == "HIGH_RISK"
    reason_parts = []
    confidence   = 0.95
    base_decision = None

    if shadow_detected:
        return {"decision": "BLOCK", "decision_confidence": 0.99,
                "reason": "Shadow agent detected — identity cannot be verified",
                "article_14_oversight_required": article_14_required,
                "suggested_policy": "block_and_alert"}

    if trust_score < 0.6:
        return {"decision": "BLOCK", "decision_confidence": 0.97,
                "reason": f"Trust score {trust_score:.2f} is below minimum threshold of 0.60",
                "article_14_oversight_required": article_14_required,
                "suggested_policy": "block_and_review"}

    if trust_score <= 0.85:
        reason_parts.append(f"Trust score {trust_score:.2f} in provisional range (0.60–0.85)")
        base_decision = "REQUIRE_HUMAN_APPROVAL"
        confidence    = 0.91
    else:
        if risk_level == "critical":
            base_decision = "REQUIRE_HUMAN_APPROVAL"
            reason_parts.append(f"Critical action in {context} context")
            confidence = 0.94
        elif risk_level == "medium":
            base_decision = "ALLOW_WITH_LOG"
            reason_parts.append("Medium-risk action — audit trail required")
            confidence = 0.92
        else:
            base_decision = "AUTO_ALLOW"
            reason_parts.append("Low-risk action with verified identity")
            confidence = 0.96

    escalation_map = {
        "AUTO_ALLOW":             "ALLOW_WITH_LOG",
        "ALLOW_WITH_LOG":         "REQUIRE_HUMAN_APPROVAL",
        "REQUIRE_HUMAN_APPROVAL": "REQUIRE_HUMAN_APPROVAL",
        "BLOCK":                  "BLOCK",
    }

    final_decision = base_decision
    if eu_risk_class == "HIGH_RISK":
        escalated = escalation_map[base_decision]
        if escalated != base_decision:
            reason_parts.append("EU AI Act HIGH_RISK classification — escalated one level")
            confidence = max(0.88, confidence - 0.04)
        final_decision = escalated

    if article_14_required and final_decision == "AUTO_ALLOW":
        final_decision = "ALLOW_WITH_LOG"

    policy_map = {
        "AUTO_ALLOW":             "auto_allow",
        "ALLOW_WITH_LOG":         "allow_with_audit_log",
        "REQUIRE_HUMAN_APPROVAL": "require_human_approval",
        "BLOCK":                  "block_and_alert",
    }

    return {
        "decision":                     final_decision,
        "decision_confidence":          round(confidence, 2),
        "reason":                       " | ".join(reason_parts) + f" | Action: {action_type}",
        "article_14_oversight_required": article_14_required,
        "suggested_policy":             policy_map[final_decision],
    }


@app.post("/v1/action/evaluate", tags=["Action Evaluation"])
async def evaluate_action(req: ActionEvaluateRequest, x_api_key: Optional[str] = Header(None)):
    """
    Should this agent be allowed to do this action?
    Returns: AUTO_ALLOW, ALLOW_WITH_LOG, REQUIRE_HUMAN_APPROVAL, or BLOCK.
    Requires x-api-key header.
    """
    require_api_key(x_api_key)

    p = await db_get("passports", "agent_id", req.agent_id)
    if not p:
        raise HTTPException(status_code=404, detail=f"Agent '{req.agent_id}' not found in VeriSigil registry.")

    shadow_detected = p.get("status") == "REVOKED"
    eu_risk_class   = p.get("eu_risk_class", "LIMITED_RISK")
    trust_score     = float(p.get("trust_score", 0.97))

    result = compute_action_decision(
        trust_score     = trust_score,
        shadow_detected = shadow_detected,
        eu_risk_class   = eu_risk_class,
        risk_level      = req.risk_level,
        action_type     = req.action_type,
        context         = req.context or "production",
    )

    await log_event(req.agent_id, "ACTION_EVALUATED", {
        "action_type":  req.action_type,
        "risk_level":   req.risk_level,
        "context":      req.context,
        "decision":     result["decision"],
        "trust_score":  trust_score,
        "eu_risk_class": eu_risk_class,
    })

    return ActionEvaluateResponse(
        decision                     = result["decision"],
        decision_confidence          = result["decision_confidence"],
        reason                       = result["reason"],
        trust_score                  = trust_score,
        shadow_detected              = shadow_detected,
        eu_risk_class                = eu_risk_class,
        article_14_oversight_required = result["article_14_oversight_required"],
        suggested_policy             = result["suggested_policy"],
        evaluation_id                = f"eval_{uuid.uuid4().hex[:8]}",
        evaluated_at                 = datetime.utcnow().isoformat() + "Z",
    )
    
