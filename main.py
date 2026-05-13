# -*- coding: utf-8 -*-
"""
VeriSigil AI - API Server v0.5.4 — Security hardened
Complete integrated main.py - all endpoints in one file.
Fix: time import conflict in Runtime Guard resolved.
"""

import asyncio
import base64, hashlib, math, os, uuid, json, re, time as time_module, smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from time import time
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from enum import Enum

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
from nacl.signing import SigningKey

# ============================================================
# ENVIRONMENT CONFIG
# ============================================================
SUPABASE_URL         = os.environ.get("SUPABASE_URL")
SUPABASE_KEY         = os.environ.get("SUPABASE_KEY")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", os.environ.get("SUPABASE_KEY"))
SIGN_SECRET          = os.environ.get("SIGN_SECRET", "")
API_KEY              = os.environ.get("VERISIGIL_API_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise Exception("SUPABASE_URL and SUPABASE_KEY must be set in environment variables")
if not API_KEY:
    raise Exception("VERISIGIL_API_KEY must be set in environment variables")

_seed          = hashlib.sha256(SIGN_SECRET.encode()).digest()
SIGNING_KEY    = SigningKey(_seed)
VERIFY_KEY     = SIGNING_KEY.verify_key
PUBLIC_KEY_B64 = base64.b64encode(bytes(VERIFY_KEY)).decode()

# ============================================================
# RATE LIMITER
# ============================================================
RATE_LIMIT_STORE: dict = {}
MAX_REQUESTS_PER_MINUTE = 10

def check_rate_limit(client_ip: str) -> bool:
    now    = time()
    window = RATE_LIMIT_STORE.get(client_ip, [])
    window = [t for t in window if now - t < 60]
    if len(window) >= MAX_REQUESTS_PER_MINUTE:
        return False
    window.append(now)
    RATE_LIMIT_STORE[client_ip] = window
    return True

# ============================================================
# APP SETUP
# ============================================================
app = FastAPI(
    title="VeriSigil AI API",
    description="The cryptographic identity and security layer for autonomous AI agents.",
    version="0.5.4",
    docs_url="/docs",
)

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

# ============================================================
# AUTH
# ============================================================
def require_api_key(x_api_key: Optional[str]):
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(401, "Invalid or missing API key. Pass your key in the x-api-key header.")

# ============================================================
# DB HELPERS
# ============================================================
def get_headers(write=False):
    key = SUPABASE_SERVICE_KEY if write else SUPABASE_KEY
    return {
        "apikey":        key,
        "Authorization": f"Bearer {key}",
        "Content-Type":  "application/json",
        "Prefer":        "return=representation",
    }

async def db_insert(table, data):
    async with httpx.AsyncClient() as c:
        r = await c.post(
            f"{SUPABASE_URL}/rest/v1/{table}",
            headers=get_headers(write=True), json=data, timeout=10
        )
        if r.status_code >= 400:
            print(f"[DB INSERT ERROR] table={table} status={r.status_code} response={r.text[:200]}")
            return {"code": r.status_code, "message": r.text[:200]}
        result = r.json()
        return result[0] if isinstance(result, list) and result else data

async def db_get(table, field, value):
    async with httpx.AsyncClient() as c:
        r = await c.get(
            f"{SUPABASE_URL}/rest/v1/{table}?{field}=eq.{value}",
            headers=get_headers(write=False), timeout=10
        )
        result = r.json()
        return result[0] if isinstance(result, list) and result else None

async def db_get_many(table, field, value, order_by=None, limit=None):
    url = f"{SUPABASE_URL}/rest/v1/{table}?{field}=eq.{value}"
    if order_by:
        url += f"&order={order_by}"
    if limit:
        url += f"&limit={limit}"
    async with httpx.AsyncClient() as c:
        r = await c.get(url, headers=get_headers(write=False), timeout=10)
        result = r.json()
        return result if isinstance(result, list) else []

async def db_patch(table, field, value, data):
    async with httpx.AsyncClient() as c:
        r = await c.patch(
            f"{SUPABASE_URL}/rest/v1/{table}?{field}=eq.{value}",
            headers=get_headers(write=True), json=data, timeout=10
        )
        if r.status_code >= 400:
            print(f"[DB PATCH ERROR] table={table} status={r.status_code} response={r.text[:200]}")
        result = r.json()
        return result[0] if isinstance(result, list) and result else data

# ============================================================
# CRYPTO
# ============================================================
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
    if not api_key or api_key == "demo":
        return {"id": "ver_public", "name": "Public", "type": "public", "reputation": 0.3}
    verifier = await db_get("verifiers", "api_key", api_key)
    return verifier

async def update_verifier_reputation(verifier_id: str, action: str = "verify"):
    verifier = await db_get("verifiers", "id", verifier_id)
    if not verifier:
        return
    rep   = verifier.get("reputation", 0.5)
    rep  += 0.01 if action == "verify" else -0.05
    rep   = max(0.1, min(1.0, round(rep, 4)))
    count = (verifier.get("verifications") or 0) + 1
    await db_patch("verifiers", "id", verifier_id, {"reputation": rep, "verifications": count})

# ============================================================
# TRUST SCORE
# ============================================================
def calculate_trust_score(issued_at: str, verification_count: int,
                           high_threats: int, medium_threats: int,
                           unique_verifiers: int = 0,
                           avg_verifier_reputation: float = 0.5) -> float:
    try:
        days = max(0, (datetime.utcnow() - datetime.fromisoformat(issued_at)).days)
    except Exception:
        days = 0
    score  = 0.97
    score -= 0.001 * days
    score -= 0.15  * (high_threats or 0)
    score -= 0.05  * (medium_threats or 0)
    effective = max(unique_verifiers or 0, verification_count or 0)
    rep       = float(avg_verifier_reputation or 0.5)
    boost     = rep * 0.005 * math.log(effective + 1)
    score    += min(boost, 0.02)
    return max(0.0, min(1.0, round(score, 4)))

def trust_level(score: float) -> str:
    if score >= 0.80: return "TRUSTED"
    if score >= 0.60: return "FLAGGED"
    return "BLOCKED"

# ============================================================
# AUDIT LOG
# ============================================================
async def log_event(agent_id: str, event: str, event_data: dict = {}):
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
        await db_patch("passports", "agent_id", agent_id, {"audit_events": existing})
    except Exception as e:
        print(f"[AUDIT ERROR] agent={agent_id} event={event} error={e}")

# ============================================================
# GEOGRAPHY
# ============================================================
def get_geo_from_request(req: Request) -> dict:
    country = (
        req.headers.get('cf-ipcountry') or
        req.headers.get('CF-IPCountry') or
        'Unknown'
    )
    REGION_MAP = {
        'NL':'EU','DE':'EU','FR':'EU','ES':'EU','IT':'EU','BE':'EU','AT':'EU',
        'PL':'EU','SE':'EU','DK':'EU','FI':'EU','IE':'EU','PT':'EU','CZ':'EU',
        'HU':'EU','GR':'EU','SK':'EU','SI':'EU','LU':'EU','LT':'EU','LV':'EU',
        'EE':'EU','CY':'EU','MT':'EU','BG':'EU','HR':'EU','RO':'EU',
        'IS':'EU','LI':'EU','NO':'EU','CH':'EU',
        'US':'NA','CA':'NA','MX':'NA',
        'SG':'APAC','JP':'APAC','KR':'APAC','IN':'APAC','AU':'APAC','NZ':'APAC',
        'TH':'APAC','VN':'APAC','MY':'APAC','ID':'APAC','PH':'APAC','TW':'APAC','HK':'APAC',
        'NG':'Africa','ZA':'Africa','KE':'Africa','GH':'Africa','EG':'Africa',
        'MA':'Africa','ET':'Africa','UG':'Africa',
        'AE':'ME','SA':'ME','QA':'ME','KW':'ME','BH':'ME','OM':'ME','JO':'ME','IL':'ME',
        'GB':'UK','UK':'UK',
    }
    return {"country": country, "region": REGION_MAP.get(country, 'Other')}

# ============================================================
# PASSPORT GENERATOR
# ============================================================
PROTECTED_NAMES = {
    "chatgpt","gpt-4","gpt-4o","gpt4","claude","grok",
    "gemini","copilot","llama","perplexity","mistral"
}

TIER_LABELS       = {0:"Self-Declared",1:"Domain-Verified",2:"Org-Verified",3:"Certified"}
TIER_BADGE_COLORS = {0:"#888888",1:"#4FC3F7",2:"#00D4F5",3:"#FFD700"}

def make_passport(agent_name, owner, framework, runtime, version, tags, expiry_days,
                  display_name=None, issuer_org=None, country='Unknown', region='Unknown'):
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
        "agent_id":          _id,
        "agent_name":        agent_name,
        "did":               did,
        "public_key":        PUBLIC_KEY_B64,
        "signature":         sign_payload({"agent_id": _id, "did": did, "issued_at": issued_at,
                                           "owner": owner, "issuer": "https://verisigilai.com"}),
        "signature_type":    "Ed25519",
        "owner":             owner,
        "issuer":            "https://verisigilai.com",
        "status":            "ACTIVE",
        "trust_score":       0.97,
        "eu_risk_class":     "LIMITED_RISK",
        "compliant":         True,
        "framework":         framework,
        "runtime":           runtime,
        "version":           version,
        "tags":              tags,
        "display_name":      display_name or agent_name,
        "issuer_org":        issuer_org or owner,
        "verification_tier": 0,
        "tier_label":        "Self-Declared",
        "tier_color":        "#888888",
        "is_protected":      agent_name.lower() in PROTECTED_NAMES,
        "issued_at":         issued_at,
        "expires_at":        exp.isoformat(),
        "threats_detected":  0,
        "eu_ai_act":         True,
        "gdpr":              True,
        "hipaa":             False,
        "soc2":              False,
        "certificate_id":    f"cert_{uuid.uuid4().hex[:16]}",
        "issued_by":         "VeriSigil AI",
        "audit_events":      [issued_event],
        "country":           country,
        "region":            region,
    }

# ============================================================
# MODELS
# ============================================================

class IssueReq(BaseModel):
    agent_name:   str
    owner:        str
    framework:    str = "unknown"
    runtime:      str = "python"
    version:      str = "1.0.0"
    tags:         List[str] = []
    expiry_days:  int = 365
    display_name: Optional[str] = None
    issuer_org:   Optional[str] = None

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

class ActionEvaluateRequest(BaseModel):
    agent_id:    str
    action_type: str
    risk_level:  str
    context:     Optional[str] = "production"

class ActionEvaluateResponse(BaseModel):
    decision:                      str
    decision_confidence:           float
    reason:                        str
    trust_score:                   float
    shadow_detected:               bool
    eu_risk_class:                 str
    article_14_oversight_required: bool
    suggested_policy:              str
    evaluation_id:                 str
    evaluated_at:                  str

class RegisterVerifierReq(BaseModel):
    name:    str
    email:   str
    company: Optional[str] = None
    website: Optional[str] = None
    type:    Optional[str] = "developer"

class WaitlistSignup(BaseModel):
    email:    str
    name:     Optional[str] = None
    company:  Optional[str] = None
    use_case: Optional[str] = None
    tier:     Optional[str] = "free"
    source:   Optional[str] = "homepage"

class SigilGuardEvent(BaseModel):
    agent_id:       str
    module:         str
    severity:       Optional[str] = "medium"
    event_type:     str
    description:    Optional[str] = None
    score_before:   Optional[float] = None
    score_after:    Optional[float] = None
    remediation:    Optional[str] = None
    remediated:     Optional[bool] = False
    remediation_ms: Optional[int] = None
    raw_payload:    Optional[dict] = {}

class PublicScanRequest(BaseModel):
    agent_config_raw: str
    agent_id:         Optional[str] = None

# ── Runtime Guard Models ──────────────────────────────────────

class Decision(str, Enum):
    ALLOW                  = "ALLOW"
    DENY                   = "DENY"
    REQUIRE_HUMAN_APPROVAL = "REQUIRE_HUMAN_APPROVAL"

class ExecutionRequest(BaseModel):
    agent_id:       str
    action_type:    str
    action_details: dict = {}
    resource:       str
    context:        str = "production"

class ExecutionResponse(BaseModel):
    decision:      Decision
    confidence:    float
    reason:        str
    agent_id:      str
    trust_score:   float
    trust_level:   str
    policy_applied: str
    execution_id:  str
    timestamp:     str
    audit_log_id:  str
    latency_ms:    float
    approval_url:  Optional[str] = None
    approval_id:   Optional[str] = None

# ── Operational Gateway Models ────────────────────────────────

class GateDecision(str, Enum):
    ALLOW                  = "ALLOW"
    DENY                   = "DENY"
    REQUIRE_HUMAN_APPROVAL = "REQUIRE_HUMAN_APPROVAL"

class VerifyRequest(BaseModel):
    agent_id:     str
    action_type:  str
    action_detail: str
    policy_mode:  str = "standard"
    context:      Optional[Dict[str, Any]] = {}

class VerifyResponse(BaseModel):
    decision:         GateDecision
    gates:            Dict[str, bool]
    trust_score:      float
    latency_ms:       float
    audit_id:         str
    eu_act_compliant: bool
    reason:           Optional[str] = None

# ============================================================
# HELPERS — Action Evaluation
# ============================================================
def compute_action_decision(trust_score, shadow_detected, eu_risk_class, risk_level, action_type, context):
    article_14_required = eu_risk_class == "HIGH_RISK"
    reason_parts  = []
    confidence    = 0.95
    base_decision = None

    if shadow_detected:
        return {"decision": "BLOCK", "decision_confidence": 0.99,
                "reason": "Shadow agent detected - identity cannot be verified",
                "article_14_oversight_required": article_14_required,
                "suggested_policy": "block_and_alert"}

    if trust_score < 0.6:
        return {"decision": "BLOCK", "decision_confidence": 0.97,
                "reason": f"Trust score {trust_score:.2f} is below minimum threshold of 0.60",
                "article_14_oversight_required": article_14_required,
                "suggested_policy": "block_and_review"}

    if trust_score <= 0.85:
        reason_parts.append(f"Trust score {trust_score:.2f} in provisional range (0.60-0.85)")
        base_decision = "REQUIRE_HUMAN_APPROVAL"
        confidence    = 0.91
    else:
        if risk_level == "critical":
            base_decision = "REQUIRE_HUMAN_APPROVAL"
            reason_parts.append(f"Critical action in {context} context")
            confidence = 0.94
        elif risk_level == "medium":
            base_decision = "ALLOW_WITH_LOG"
            reason_parts.append("Medium-risk action - audit trail required")
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
            reason_parts.append("EU AI Act HIGH_RISK - escalated one level")
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
        "decision":                      final_decision,
        "decision_confidence":           round(confidence, 2),
        "reason":                        " | ".join(reason_parts) + f" | Action: {action_type}",
        "article_14_oversight_required": article_14_required,
        "suggested_policy":              policy_map[final_decision],
    }

# ============================================================
# HELPERS — Runtime Guard
# ============================================================

POLICY_RULES = {
    "payment":     {"max_amount_usd": 1000, "require_human_if_high_risk": True},
    "data_access": {"require_audit": True, "block_pii_if_not_gdpr": True},
    "tool_use":    {"blocked_tools": ["exec", "eval", "shell", "file_delete"]},
}

POLICY_THRESHOLDS = {
    "strict":     {"min_trust_score": 0.90, "max_amount_usd": 1000,   "require_human_for": ["transfer","delete","deploy"]},
    "standard":   {"min_trust_score": 0.75, "max_amount_usd": 10000,  "require_human_for": ["transfer"]},
    "permissive": {"min_trust_score": 0.60, "max_amount_usd": 100000, "require_human_for": []},
}

async def check_shadow_status(agent_id: str) -> bool:
    passport = await db_get("passports", "agent_id", agent_id)
    if not passport:
        return False
    did = passport.get("did", "")
    async with httpx.AsyncClient() as c:
        r = await c.get(
            f"{SUPABASE_URL}/rest/v1/passports?did=eq.{did}&agent_id=neq.{agent_id}",
            headers=get_headers(write=False), timeout=5
        )
        collisions = r.json() if r.status_code == 200 else []
    return len(collisions) > 0

def _deny_exec_response(agent_id: str, reason: str, start_time: float) -> ExecutionResponse:
    return ExecutionResponse(
        decision=Decision.DENY, confidence=0.99, reason=reason,
        agent_id=agent_id, trust_score=0.0, trust_level="UNKNOWN",
        policy_applied="identity_verification",
        execution_id=f"exec_{uuid.uuid4().hex[:8]}",
        timestamp=datetime.utcnow().isoformat(),
        audit_log_id="none",
        latency_ms=round((time_module.time() - start_time) * 1000, 2)
    )

def _deny_gate_response(agent_id: str, reason: str, gates: dict, start_time: float) -> VerifyResponse:
    return VerifyResponse(
        decision=GateDecision.DENY,
        gates=gates,
        trust_score=0.0,
        latency_ms=round((time_module.time() - start_time) * 1000, 2),
        audit_id=f"evt_{uuid.uuid4().hex[:8]}",
        eu_act_compliant=True,
        reason=reason
    )

def _evaluate_decision(sig_valid, is_revoked, is_expired, shadow_detected,
                       trust_score, action_type, action_details, policy) -> tuple:
    reasons = []
    if not sig_valid:
        return Decision.DENY, 0.99, ["Invalid cryptographic signature — possible forgery"]
    if is_revoked:
        return Decision.DENY, 0.99, ["Agent passport revoked"]
    if is_expired:
        return Decision.DENY, 0.98, ["Agent passport expired"]
    if shadow_detected:
        return Decision.DENY, 0.99, ["Shadow clone detected — identity conflict"]
    if trust_score < 0.60:
        return Decision.DENY, 0.97, [f"Trust score {trust_score:.2f} below minimum threshold (0.60)"]
    if trust_score < 0.85:
        return Decision.REQUIRE_HUMAN_APPROVAL, 0.91, [f"Trust score {trust_score:.2f} in provisional range — human oversight required"]

    if action_type == "payment":
        amount = action_details.get("amount_usd", 0)
        if amount > policy.get("max_amount_usd", 1000):
            return Decision.REQUIRE_HUMAN_APPROVAL, 0.94, [f"Payment ${amount} exceeds auto-allow threshold"]

    if action_type == "tool_use":
        tool = action_details.get("tool_name", "")
        if tool in policy.get("blocked_tools", []):
            return Decision.DENY, 0.96, [f"Tool '{tool}' is blocked for this agent"]

    if action_type == "data_access":
        if action_details.get("contains_pii", False) and not policy.get("gdpr_allowed", False):
            return Decision.DENY, 0.95, ["PII access requires GDPR-certified agent"]

    reasons.append(f"Trust score {trust_score:.2f} sufficient for {action_type}")
    if policy.get("require_audit", False):
        reasons.append("Audit trail required — logged")
    return Decision.ALLOW, 0.95, reasons

# ============================================================
# ROUTES
# ============================================================

@app.get("/")
async def root():
    return {
        "name":           "VeriSigil AI API",
        "version":        "0.5.4",
        "status":         "live",
        "description":    "Cryptographic identity and security for autonomous AI agents.",
        "website":        "https://www.verisigilai.com",
        "docs":           "/docs",
        "public_key":     PUBLIC_KEY_B64,
        "signature_type": "Ed25519",
        "auth":           "Pass your API key in the x-api-key header for protected endpoints.",
        "endpoints": {
            "issue":             "POST /v1/passport/issue            [requires x-api-key]",
            "get":               "GET  /v1/passport/{agent_id}       [public]",
            "profile":           "GET  /v1/passport/{agent_id}/profile [public]",
            "audit":             "GET  /v1/passport/{agent_id}/audit  [public]",
            "verify":            "GET  /verify/{agent_id}             [public]",
            "did":               "GET  /did/{agent_id}                [public]",
            "revoke":            "POST /v1/passport/revoke            [requires x-api-key]",
            "scan_secure":       "POST /v1/security/scan              [requires x-api-key]",
            "scan_public":       "POST /v1/scan                       [public]",
            "compliance":        "POST /v1/compliance/check           [requires x-api-key]",
            "action_evaluate":   "POST /v1/action/evaluate            [requires x-api-key]",
            "verifier_register": "POST /v1/verifier/register          [public]",
            "verifier_list":     "GET  /v1/verifiers                  [requires x-api-key]",
            "trust_graph":       "GET  /v1/trust/{agent_id}/graph     [public]",
            "waitlist":          "POST /v1/waitlist                   [public]",
            "sigilguard_event":  "POST /v1/sigilguard/event           [requires x-api-key]",
            "sigilguard_stats":  "GET  /v1/sigilguard/stats/{agent_id} [public]",
            "guard_verify":      "POST /v1/guard/verify               [requires x-api-key]",
            "gate_verify":       "POST /v1/verify                     [requires x-api-key]",
            "guard_sdk":         "GET  /v1/guard/sdk                  [requires x-api-key]",
            "sprint_run":        "POST /v1/sprint/run                 [requires x-api-key]",
        }
    }

@app.get("/health")
async def health():
    return {"status": "healthy", "version": "0.5.4"}

# ── PASSPORT ISSUE ────────────────────────────────────────────

@app.get("/issue-test")
async def issue_test(req: Request):
    geo = get_geo_from_request(req)
    p   = make_passport(
        "verisigil-test-agent", "raheem@verisigilai.com",
        "langchain", "python", "1.0.0", ["test"], 365,
        country=geo["country"], region=geo["region"]
    )
    db_record = {k: p[k] for k in [
        "agent_id","agent_name","did","public_key","signature","signature_type",
        "owner","issuer","status","trust_score","eu_risk_class","compliant",
        "framework","runtime","version","tags","display_name","issuer_org",
        "verification_tier","tier_label","issued_at","expires_at",
        "eu_ai_act","gdpr","hipaa","soc2","country","region",
    ] if k in p}
    db_record["is_protected_name"] = p.get("is_protected", False)
    try:
        await db_insert("passports", db_record)
        p["stored"] = True
    except Exception as e:
        p["stored"] = False
        p["error"]  = str(e)
    return {"success": True, "passport": p, "geography": geo}

@app.post("/v1/passport/issue")
async def issue(req: IssueReq, request: Request, x_api_key: Optional[str] = Header(None)):
    require_api_key(x_api_key)
    geo        = get_geo_from_request(request)
    check_name = (req.display_name or req.agent_name).lower().strip()
    if check_name in PROTECTED_NAMES:
        raise HTTPException(status_code=403, detail={
            "error":           "PROTECTED_NAME",
            "message":         f"'{req.display_name or req.agent_name}' is a reserved name.",
            "protected_names": "ChatGPT, Grok, Claude, Gemini, Copilot, Llama, Perplexity, Mistral"
        })
    p = make_passport(
        req.agent_name, req.owner, req.framework, req.runtime,
        req.version, req.tags, req.expiry_days,
        display_name=req.display_name, issuer_org=req.issuer_org,
        country=geo["country"], region=geo["region"]
    )
    db_record = {
        "agent_id": p["agent_id"], "agent_name": p["agent_name"], "did": p["did"],
        "public_key": p["public_key"], "signature": p["signature"],
        "signature_type": p["signature_type"], "owner": p["owner"], "issuer": p["issuer"],
        "status": p["status"], "trust_score": p["trust_score"],
        "eu_risk_class": p["eu_risk_class"], "compliant": p["compliant"],
        "framework": p["framework"], "runtime": p["runtime"], "version": p["version"],
        "tags": p["tags"], "display_name": p["display_name"], "issuer_org": p["issuer_org"],
        "verification_tier": p["verification_tier"], "tier_label": p["tier_label"],
        "is_protected_name": p["is_protected"], "issued_at": p["issued_at"],
        "expires_at": p["expires_at"], "eu_ai_act": p["eu_ai_act"],
        "gdpr": p["gdpr"], "hipaa": p["hipaa"], "soc2": p["soc2"],
        "country": p["country"], "region": p["region"],
    }
    try:
        result = await db_insert("passports", db_record)
        p["stored"] = not (isinstance(result, dict) and result.get("code"))
        if not p["stored"]:
            p["db_error"] = result.get("message", "DB insert rejected")
    except Exception as e:
        p["stored"]   = False
        p["db_error"] = str(e)
    return {"success": True, "passport": p, "geography": geo}

# ── PASSPORT GET / AUDIT / REVOKE ─────────────────────────────

@app.get("/v1/passport/{agent_id}/audit")
async def get_audit(agent_id: str):
    p = await db_get("passports", "agent_id", agent_id)
    if not p:
        raise HTTPException(404, "Passport not found.")
    events   = p.get("audit_events") or []
    verified = []
    for e in events:
        sig_valid = verify_payload(
            {"agent_id": agent_id, "event": e["event"], "timestamp": e["timestamp"]},
            e.get("signature", ""))
        verified.append({**e, "signature_valid": sig_valid})
    return {"agent_id": agent_id, "total_events": len(verified), "audit_log": verified,
            "public_key": PUBLIC_KEY_B64, "signature_type": "Ed25519", "issued_by": "VeriSigil AI"}

@app.get("/v1/passport/{agent_id}/profile")
async def get_passport_profile(agent_id: str):
    p = await db_get("passports", "agent_id", agent_id)
    if not p:
        raise HTTPException(404, "Passport not found.")
    passport_db_id = p.get("id")
    history   = await db_get_many("trust_score_history", "agent_id", passport_db_id, order_by="recorded_at.desc", limit=10)
    sg_events = await db_get_many("sigilguard_events",   "agent_id", passport_db_id, order_by="detected_at.desc",  limit=5)
    return {
        "agent_id":          p.get("agent_id"),
        "agent_name":        p.get("display_name") or p.get("agent_name"),
        "built_by":          p.get("issuer_org"),
        "did":               p.get("did"),
        "trust_score":       p.get("trust_score"),
        "trust_level":       trust_level(float(p.get("trust_score", 0.97))),
        "eu_risk_class":     p.get("eu_risk_class", "LIMITED_RISK"),
        "eu_act_status":     "COMPLIANT" if p.get("compliant") else "PENDING",
        "status":            p.get("status", "ACTIVE"),
        "framework":         p.get("framework"),
        "verification_tier": p.get("verification_tier", 0),
        "tier_label":        p.get("tier_label", "Self-Declared"),
        "issued_at":         p.get("issued_at"),
        "expires_at":        p.get("expires_at"),
        "country":           p.get("country"),
        "region":            p.get("region"),
        "trust_history":     history,
        "sigilguard_events": sg_events,
        "audit_events":      (p.get("audit_events") or [])[-5:],
    }

@app.get("/v1/passport/{agent_id}")
async def get_p(agent_id: str):
    p = await db_get("passports", "agent_id", agent_id)
    if not p:
        raise HTTPException(404, "Passport not found.")
    return {"success": True, "passport": p}

@app.post("/v1/passport/revoke")
async def revoke(req: RevokeReq, x_api_key: Optional[str] = Header(None)):
    require_api_key(x_api_key)
    p = await db_get("passports", "agent_id", req.agent_id)
    if not p:
        raise HTTPException(404, "Passport not found.")
    await db_patch("passports", "agent_id", req.agent_id, {
        "status": "REVOKED", "revoked_at": datetime.utcnow().isoformat(), "revoke_reason": req.reason})
    await log_event(req.agent_id, "REVOKED", {"reason": req.reason})
    return {"revoked": True, "agent_id": req.agent_id, "reason": req.reason}

# ── VERIFY & DID ──────────────────────────────────────────────

@app.get("/verify/{agent_id}")
async def verify_get(agent_id: str, request: Request, x_api_key: Optional[str] = Header(None)):
    try:
        client_ip = request.client.host if request.client else "unknown"
        if not check_rate_limit(client_ip):
            raise HTTPException(429, "Too many requests - max 10/min per IP.")
        p = await db_get("passports", "agent_id", agent_id)
        if not p:
            return {"valid": False, "verified": False, "agent_id": agent_id,
                    "reason": "Passport not found.", "issuer": "verisigilai.com"}
        sig_valid   = verify_payload(
            {"agent_id": p["agent_id"], "did": p["did"], "issued_at": p["issued_at"],
             "owner": p["owner"], "issuer": "https://verisigilai.com"},
            p.get("signature", ""))
        is_active   = p.get("status") == "ACTIVE"
        not_expired = datetime.utcnow() < datetime.fromisoformat(p["expires_at"])
        try:
            verifier = await get_verifier(x_api_key)
        except Exception:
            verifier = {"id": "ver_public", "type": "public", "reputation": 0.3}
        verifier_id  = verifier.get("id", "ver_public")
        verifier_rep = float(verifier.get("reputation", 0.3))
        existing_events    = p.get("audit_events") or []
        all_verifier_ids   = [e.get("event_data", {}).get("verifier_id")
                               for e in existing_events if e.get("event") == "VERIFIED"] + [verifier_id]
        unique_verifier_count = len(set(v for v in all_verifier_ids if v))
        recent_ids   = [e.get("event_data", {}).get("verifier_id")
                        for e in existing_events[-5:] if e.get("event") == "VERIFIED"]
        is_duplicate = verifier_id in recent_ids
        new_count    = (p.get("verification_count") or 0) + 1
        new_score    = calculate_trust_score(
            p["issued_at"], new_count,
            p.get("high_threats") or 0, p.get("medium_threats") or 0,
            unique_verifiers=unique_verifier_count, avg_verifier_reputation=verifier_rep)
        if not is_duplicate:
            try:
                await db_patch("passports", "agent_id", agent_id,
                               {"verification_count": new_count, "trust_score": new_score})
            except Exception as e:
                print(f"[VERIFY PATCH ERROR] {e}")
        try:
            await log_event(agent_id, "VERIFIED", {
                "method": "GET /verify", "verifier_id": verifier_id,
                "verifier_type": verifier.get("type", "public"),
                "verifier_reputation": verifier_rep, "verification_count": new_count,
                "unique_verifiers": unique_verifier_count, "trust_score": new_score,
                "trust_level": trust_level(new_score), "duplicate": is_duplicate})
        except Exception as e:
            print(f"[VERIFY LOG ERROR] {e}")
        return {
            "valid": sig_valid and is_active and not_expired, "verified": sig_valid,
            "agent_id": agent_id, "did": p.get("did"), "status": p.get("status"),
            "trust_score": new_score, "trust_level": trust_level(new_score),
            "verification_count": new_count, "unique_verifiers": unique_verifier_count,
            "signature_valid": sig_valid, "signature_type": "Ed25519",
            "public_key": PUBLIC_KEY_B64, "issuer": "verisigilai.com",
            "issued_at": p.get("issued_at"), "expires_at": p.get("expires_at"),
            "compliant": p.get("compliant"), "eu_ai_act": p.get("eu_ai_act"),
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"[VERIFY ERROR] agent={agent_id} error={e}")
        raise HTTPException(500, f"Verification error: {str(e)}")

@app.get("/did/{agent_id}")
async def did_resolution(agent_id: str):
    p = await db_get("passports", "agent_id", agent_id)
    if not p:
        raise HTTPException(404, {"error": "notFound", "message": f"DID not found for {agent_id}"})
    did     = p.get("did")
    pub_key = p.get("public_key", PUBLIC_KEY_B64)
    return {
        "@context": ["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/ed25519-2020/v1"],
        "id": did, "controller": "did:web:verisigilai.com",
        "verificationMethod": [{"id": f"{did}#key-1", "type": "Ed25519VerificationKey2020",
                                  "controller": did,
                                  "publicKeyMultibase": "z" + base64.b64encode(base64.b64decode(pub_key)).decode()}],
        "authentication": [f"{did}#key-1"], "assertionMethod": [f"{did}#key-1"],
        "service": [{"id": f"{did}#verisigil", "type": "VeriSigilPassportService",
                     "serviceEndpoint": f"https://verisigil-api-production.up.railway.app/verify/{agent_id}"}],
        "metadata": {"agent_id": agent_id, "agent_name": p.get("agent_name"),
                     "status": p.get("status"), "trust_score": p.get("trust_score"),
                     "issued_at": p.get("issued_at"), "expires_at": p.get("expires_at"),
                     "issuer": "VeriSigil AI", "eu_ai_act": p.get("eu_ai_act"), "compliant": p.get("compliant")}
    }

# ── SECURITY SCAN ─────────────────────────────────────────────

@app.post("/v1/security/scan")
async def scan(req: ScanReq, x_api_key: Optional[str] = Header(None)):
    require_api_key(x_api_key)
    threats, seen = [], set()
    lines    = req.code.split("\n")
    patterns = [
        ("eval(",       "HIGH",   "Unsafe eval() - arbitrary code execution risk"),
        ("exec(",       "HIGH",   "Unsafe exec() - arbitrary code execution risk"),
        ("subprocess",  "MEDIUM", "Subprocess call - verify inputs are sanitised"),
        ("os.system",   "HIGH",   "Direct OS command execution"),
        ("pickle.load", "HIGH",   "Unsafe deserialisation - use JSON"),
        ("password",    "HIGH",   "Possible hardcoded credential"),
        ("api_key",     "HIGH",   "Possible hardcoded API key"),
        ("secret",      "HIGH",   "Possible hardcoded secret"),
    ]
    for i, line in enumerate(lines, 1):
        for pat, sev, desc in patterns:
            k = f"{i}:{pat}"
            if pat.lower() in line.lower() and k not in seen:
                seen.add(k)
                threats.append({"line": i, "severity": sev, "description": desc, "code": line.strip()})
    new_score = None
    if req.agent_id:
        high_count   = sum(1 for t in threats if t["severity"] == "HIGH")
        medium_count = sum(1 for t in threats if t["severity"] == "MEDIUM")
        passport     = await db_get("passports", "agent_id", req.agent_id)
        if passport:
            new_high   = (passport.get("high_threats")   or 0) + high_count
            new_medium = (passport.get("medium_threats") or 0) + medium_count
            new_score  = calculate_trust_score(passport["issued_at"], passport.get("verification_count", 0),
                                               new_high, new_medium)
            await db_patch("passports", "agent_id", req.agent_id,
                           {"high_threats": new_high, "medium_threats": new_medium, "trust_score": new_score})
        await log_event(req.agent_id, "SCANNED", {
            "lines_scanned": len(lines), "threats_found": len(threats),
            "high_threats": high_count, "medium_threats": medium_count, "new_trust_score": new_score})
    return {
        "scan_id": f"scan_{uuid.uuid4().hex[:12]}", "agent_id": req.agent_id,
        "lines_scanned": len(lines), "threats": threats, "threat_count": len(threats),
        "severity_summary": {
            "HIGH":   sum(1 for t in threats if t["severity"] == "HIGH"),
            "MEDIUM": sum(1 for t in threats if t["severity"] == "MEDIUM"),
            "LOW":    0},
        "passed": len(threats) == 0, "scanned_at": datetime.utcnow().isoformat()}

# ── COMPLIANCE ────────────────────────────────────────────────

@app.post("/v1/compliance/check")
async def compliance(req: ComplianceReq, x_api_key: Optional[str] = Header(None)):
    require_api_key(x_api_key)
    result = {}
    if "eu_ai_act" in req.regulations:
        result["eu_ai_act"] = {"compliant": True, "risk_class": "LIMITED_RISK", "deadline": "2026-08-01",
                                "note": "Designed for EU AI Act alignment - certification in progress"}
    if "gdpr"  in req.regulations: result["gdpr"]  = {"compliant": True, "lawful_basis": "legitimate_interest"}
    if "hipaa" in req.regulations: result["hipaa"] = {"compliant": False, "reason": "BAA required - contact info@verisigilai.com"}
    if "soc2"  in req.regulations: result["soc2"]  = {"compliant": False, "reason": "SOC 2 audit in progress - Q4 2026"}
    await log_event(req.agent_id, "COMPLIANCE_CHECKED", {"regulations": req.regulations})
    return {"agent_id": req.agent_id, "checked_at": datetime.utcnow().isoformat(), "regulations": result}

# ── ACTION EVALUATE ───────────────────────────────────────────

@app.post("/v1/action/evaluate", tags=["Action Evaluation"])
async def evaluate_action(req: ActionEvaluateRequest, x_api_key: Optional[str] = Header(None)):
    require_api_key(x_api_key)
    p = await db_get("passports", "agent_id", req.agent_id)
    if not p:
        raise HTTPException(404, f"Agent '{req.agent_id}' not found in VeriSigil registry.")
    shadow_detected = p.get("status") == "REVOKED"
    eu_risk_class   = p.get("eu_risk_class", "LIMITED_RISK")
    trust_score     = float(p.get("trust_score", 0.97))
    result = compute_action_decision(
        trust_score=trust_score, shadow_detected=shadow_detected,
        eu_risk_class=eu_risk_class, risk_level=req.risk_level,
        action_type=req.action_type, context=req.context or "production")
    await log_event(req.agent_id, "ACTION_EVALUATED", {
        "action_type": req.action_type, "risk_level": req.risk_level,
        "context": req.context, "decision": result["decision"],
        "trust_score": trust_score, "eu_risk_class": eu_risk_class})
    return ActionEvaluateResponse(
        decision=result["decision"], decision_confidence=result["decision_confidence"],
        reason=result["reason"], trust_score=trust_score, shadow_detected=shadow_detected,
        eu_risk_class=eu_risk_class,
        article_14_oversight_required=result["article_14_oversight_required"],
        suggested_policy=result["suggested_policy"],
        evaluation_id=f"eval_{uuid.uuid4().hex[:8]}",
        evaluated_at=datetime.utcnow().isoformat() + "Z")

# ── TRUST GRAPH ───────────────────────────────────────────────

@app.get("/v1/trust/{agent_id}/graph")
async def trust_graph(agent_id: str):
    p = await db_get("passports", "agent_id", agent_id)
    if not p:
        raise HTTPException(404, "Passport not found.")
    events, nodes, edges, seen_verifiers = p.get("audit_events") or [], [], [], set()
    for e in events:
        if e.get("event") != "VERIFIED": continue
        v_id   = e.get("event_data", {}).get("verifier_id", "ver_public")
        v_rep  = e.get("event_data", {}).get("verifier_reputation", 0.3)
        v_type = e.get("event_data", {}).get("verifier_type", "public")
        ts     = e.get("timestamp", "")
        if v_id not in seen_verifiers:
            nodes.append({"id": v_id, "type": "verifier", "verifier_type": v_type,
                           "reputation": v_rep, "label": v_id})
            seen_verifiers.add(v_id)
        edges.append({"from": v_id, "to": agent_id, "type": "verified", "timestamp": ts})
    nodes.append({"id": agent_id, "type": "agent", "trust_score": p.get("trust_score", 0.97),
                   "trust_level": trust_level(p.get("trust_score", 0.97)), "label": agent_id})
    return {"agent_id": agent_id, "trust_score": p.get("trust_score", 0.97),
            "trust_level": trust_level(p.get("trust_score", 0.97)),
            "unique_verifiers": len(seen_verifiers), "total_verifications": len(edges),
            "nodes": nodes, "edges": edges}

# ── VERIFIER REGISTRATION ─────────────────────────────────────

@app.post("/v1/verifier/register", tags=["Verifiers"])
async def register_verifier(req: RegisterVerifierReq):
    existing = await db_get("verifiers", "email", req.email)
    if existing:
        return {"success": True, "message": "You are already registered as a verifier.",
                "verifier_id": existing.get("id"), "api_key": existing.get("api_key")}
    verifier_id = f"ver_{uuid.uuid4().hex[:8]}"
    api_key     = f"vvk_{uuid.uuid4().hex[:24]}"
    now         = datetime.utcnow().isoformat()
    record      = {"id": verifier_id, "name": req.name, "email": req.email,
                   "company": req.company or "", "website": req.website or "",
                   "type": req.type or "developer", "api_key": api_key,
                   "reputation": 0.5, "verifications": 0, "active": True, "created_at": now}
    try:
        await db_insert("verifiers", record)
        stored = True
    except Exception as e:
        stored = False
        print(f"[VERIFIER REGISTER ERROR] {e}")
    return {"success": stored, "verifier_id": verifier_id, "api_key": api_key,
            "name": req.name, "email": req.email, "company": req.company,
            "registered_at": now,
            "message": "Welcome to VeriSigil! Use your api_key in the x-api-key header when calling /verify endpoints."}

@app.get("/v1/verifiers", tags=["Verifiers"])
async def list_verifiers(x_api_key: Optional[str] = Header(None)):
    require_api_key(x_api_key)
    async with httpx.AsyncClient() as c:
        r = await c.get(f"{SUPABASE_URL}/rest/v1/verifiers?order=created_at.desc",
                        headers=get_headers(write=False), timeout=10)
        verifiers = r.json() if r.status_code == 200 else []
    return {"total": len(verifiers), "verifiers": verifiers}

# ── WAITLIST ──────────────────────────────────────────────────

@app.post("/v1/waitlist", tags=["Waitlist"])
async def join_waitlist(data: WaitlistSignup):
    try:
        await db_insert("waitlist", {
            "email": data.email, "name": data.name, "company": data.company,
            "use_case": data.use_case, "tier": data.tier, "source": data.source, "status": "pending"})
        return {"success": True, "message": "You're on the early access list!", "email": data.email}
    except Exception as e:
        if "duplicate" in str(e).lower() or "unique" in str(e).lower():
            return {"success": True, "message": "You're already on the list!", "email": data.email}
        raise HTTPException(status_code=500, detail=str(e))

# ── SIGILGUARD ────────────────────────────────────────────────

@app.post("/v1/sigilguard/event", tags=["SigilGuard"])
async def log_sigilguard_event(event: SigilGuardEvent, x_api_key: Optional[str] = Header(None)):
    require_api_key(x_api_key)
    try:
        result = await db_insert("sigilguard_events", {
            "agent_id": event.agent_id, "module": event.module, "severity": event.severity,
            "event_type": event.event_type, "description": event.description,
            "score_before": event.score_before, "score_after": event.score_after,
            "remediation": event.remediation, "remediated": event.remediated,
            "remediation_ms": event.remediation_ms, "eu_act_logged": True,
            "raw_payload": event.raw_payload, "detected_at": datetime.utcnow().isoformat()})
        if event.score_after is not None:
            delta = round(event.score_after - event.score_before, 2) if event.score_before is not None else None
            await db_insert("trust_score_history", {
                "agent_id": event.agent_id, "score": event.score_after, "score_delta": delta,
                "reason": f"{event.module} - {event.event_type}", "recorded_at": datetime.utcnow().isoformat()})
            await db_patch("passports", "agent_id", event.agent_id, {"trust_score": event.score_after})
        return {"success": True, "event_id": result.get("id") if isinstance(result, dict) else None,
                "module": event.module, "remediated": event.remediated, "logged_at": datetime.utcnow().isoformat()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/v1/sigilguard/stats/{agent_id}", tags=["SigilGuard"])
async def get_sigilguard_stats(agent_id: str):
    p = await db_get("passports", "agent_id", agent_id)
    if not p:
        raise HTTPException(404, "Agent not found.")
    passport_db_id = p.get("id")
    events     = await db_get_many("sigilguard_events", "agent_id", passport_db_id)
    total      = len(events)
    remediated = sum(1 for e in events if e.get("remediated"))
    ms_list    = [e["remediation_ms"] for e in events if e.get("remediation_ms")]
    avg_ms     = round(sum(ms_list) / len(ms_list), 1) if ms_list else 0
    return {
        "agent_id": agent_id, "trust_score": p.get("trust_score"),
        "total_events": total, "remediated": remediated, "avg_remediation_ms": avg_ms,
        "by_module": {
            "driftguard":           sum(1 for e in events if e.get("module") == "driftguard"),
            "hallucination_shield": sum(1 for e in events if e.get("module") == "hallucination_shield"),
            "cross_modal_sync":     sum(1 for e in events if e.get("module") == "cross_modal_sync"),
            "edgeguard":            sum(1 for e in events if e.get("module") == "edgeguard")}}

# ── PUBLIC SCANNER ────────────────────────────────────────────

@app.post("/v1/scan", tags=["Scanner"])
async def public_scan(req: PublicScanRequest):
    config = req.agent_config_raw.lower()
    checks = [
        {"label": "Unsafe eval() usage",             "severity": "high",   "score": 25,
         "detail": "eval() allows arbitrary code execution",
         "fix":    "Replace with safe_eval() or ast.literal_eval()",
         "trigger": "eval(" in config},
        {"label": "Hardcoded secrets detected",       "severity": "high",   "score": 25,
         "detail": "API keys or passwords hardcoded in config",
         "fix":    "Move secrets to environment variables",
         "trigger": any(k in config for k in ["api_key =", "password =", "secret =", "token ="])},
        {"label": "No authentication defined",        "severity": "medium", "score": 15,
         "detail": "Agent has no identity or auth mechanism",
         "fix":    "Add VeriSigil passport authentication",
         "trigger": "auth" not in config and "passport" not in config},
        {"label": "Unsafe subprocess execution",      "severity": "medium", "score": 20,
         "detail": "Uncontrolled subprocess calls can execute system commands",
         "fix":    "Sandbox subprocess calls with strict allowlists",
         "trigger": "subprocess" in config or "os.system" in config},
        {"label": "No audit logging configured",      "severity": "medium", "score": 15,
         "detail": "EU AI Act requires immutable audit trails",
         "fix":    "Enable VeriSigil audit logging",
         "trigger": "audit" not in config and "log" not in config},
        {"label": "No rate limiting",                 "severity": "low",    "score": 10,
         "detail": "Agent has no rate limiting - vulnerable to abuse",
         "fix":    "Add rate limiting to all agent endpoints",
         "trigger": "rate_limit" not in config and "throttle" not in config},
        {"label": "No EU AI Act risk classification", "severity": "medium", "score": 15,
         "detail": "Agent has no EU risk level declared",
         "fix":    "Add eu_risk_level to your passport config",
         "trigger": "eu_risk" not in config and "risk_level" not in config},
        {"label": "No execution timeout defined",     "severity": "low",    "score": 10,
         "detail": "Agents without timeouts can run indefinitely",
         "fix":    "Set max_execution_time in agent config",
         "trigger": "timeout" not in config and "max_execution" not in config},
    ]
    findings, risk_score, checks_failed, checks_passed = [], 0, 0, 0
    for check in checks:
        if check["trigger"]:
            findings.append({"check": check["label"], "severity": check["severity"],
                              "detail": check["detail"], "fix": check["fix"]})
            risk_score   += check["score"]
            checks_failed += 1
        else:
            checks_passed += 1
    risk_score = min(risk_score, 100)
    risk_level_str = ("critical" if risk_score >= 70 else "high" if risk_score >= 40
                      else "medium" if risk_score >= 20 else "low")
    scan_id   = f"scan_{uuid.uuid4().hex[:12]}"
    share_url = f"https://verisigilai.com/scan.html?id={scan_id}"
    try:
        await db_insert("scan_reports", {
            "scan_id": scan_id, "agent_id": req.agent_id,
            "agent_config_raw": req.agent_config_raw[:2000],
            "risk_score": risk_score, "risk_level": risk_level_str,
            "findings": findings, "checks_passed": checks_passed,
            "checks_failed": checks_failed, "checks_total": 8, "share_url": share_url})
    except Exception as e:
        print(f"[SCAN SAVE ERROR] {e}")
    return {"scan_id": scan_id, "risk_score": risk_score, "risk_level": risk_level_str,
            "checks_passed": checks_passed, "checks_failed": checks_failed, "checks_total": 8,
            "findings": findings, "share_url": share_url, "scanned_at": datetime.utcnow().isoformat()}

# ============================================================
# v0.5.1 — RUNTIME GUARD (time import fix applied)
# ============================================================

@app.post("/v1/guard/verify", tags=["Runtime Guard"])
async def verify_before_execution(
    req: ExecutionRequest,
    request: Request,
    x_api_key: Optional[str] = Header(None)
):
    """
    OPERATIONAL RUNTIME GUARD
    Every AI agent action goes through this gate.
    Returns ALLOW / DENY / REQUIRE_HUMAN_APPROVAL in <50ms.
    """
    start_time = time_module.time()  # FIX: use time_module not time.time()
    require_api_key(x_api_key)

    passport = await db_get("passports", "agent_id", req.agent_id)
    if not passport:
        return _deny_exec_response(req.agent_id, "Agent not found in VeriSigil registry", start_time)

    sig_valid = verify_payload(
        {"agent_id": passport["agent_id"], "did": passport["did"],
         "issued_at": passport["issued_at"], "owner": passport["owner"],
         "issuer": "https://verisigilai.com"},
        passport.get("signature", ""))
    is_revoked      = passport.get("status") == "REVOKED"
    is_expired      = datetime.utcnow() > datetime.fromisoformat(passport["expires_at"])
    shadow_detected = await check_shadow_status(req.agent_id)
    trust_score     = float(passport.get("trust_score", 0.5))
    trust_level_str = trust_level(trust_score)

    policy   = POLICY_RULES.get(req.action_type, {})
    decision, confidence, reasons = _evaluate_decision(
        sig_valid, is_revoked, is_expired, shadow_detected,
        trust_score, req.action_type, req.action_details, policy)

    execution_id = f"exec_{uuid.uuid4().hex[:8]}"
    timestamp    = datetime.utcnow().isoformat()
    latency      = round((time_module.time() - start_time) * 1000, 2)  # FIX

    # Auto-create approval request when human approval is needed
    approval_url = None
    if decision == Decision.REQUIRE_HUMAN_APPROVAL:
        try:
            approval_id  = f"apr_{uuid.uuid4().hex[:8]}"
            approval_url = f"https://verisigilai.com/approve.html?id={approval_id}"
            now        = datetime.utcnow()
            expires    = now + timedelta(hours=24)
            insert_result = await db_insert("approval_requests", {
                "id":             approval_id,
                "execution_id":   execution_id,
                "agent_id":       req.agent_id,
                "action_type":    req.action_type,
                "action_details": req.action_details,
                "resource":       req.resource,
                "trust_score":    float(trust_score),
                "reason":         " | ".join(reasons),
                "status":         "pending",
                "expires_at":     expires.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
                "created_at":     now.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
            })
            print(f"[APPROVAL CREATED] {approval_id} | result: {insert_result}")

            # Send email notification to approver if email provided
            approver_notify = req.action_details.get("approver_email")
            if not approver_notify:
                approver_notify = os.environ.get("DEFAULT_APPROVER_EMAIL", "raheem@verisigilai.com")

            passport = await db_get("passports", "agent_id", req.agent_id)
            agent_display = passport.get("display_name", req.agent_id) if passport else req.agent_id

            asyncio.create_task(send_approval_email(
                approver_email  = approver_notify,
                agent_name      = agent_display,
                agent_id        = req.agent_id,
                action_type     = req.action_type,
                action_details  = req.action_details,
                reason          = " | ".join(reasons),
                trust_score     = trust_score,
                approval_id     = approval_id,
                approval_url    = approval_url,
                execution_id    = execution_id
            ))
        except Exception as e:
            print(f"[APPROVAL CREATE ERROR] {e}")
            approval_url = None

    await log_event(req.agent_id, "EXECUTION_EVALUATED", {
        "execution_id": execution_id, "action_type": req.action_type,
        "decision": decision.value, "reason": " | ".join(reasons),
        "trust_score": trust_score, "latency_ms": latency,
        "approval_url": approval_url})

    return ExecutionResponse(
        decision=decision, confidence=confidence, reason=" | ".join(reasons),
        agent_id=req.agent_id, trust_score=trust_score, trust_level=trust_level_str,
        policy_applied=req.action_type, execution_id=execution_id,
        timestamp=timestamp, audit_log_id=execution_id, latency_ms=latency,
        approval_url=approval_url if decision == Decision.REQUIRE_HUMAN_APPROVAL else None,
        approval_id=approval_url.split("id=")[-1] if approval_url else None)

# ── OPERATIONAL GATEWAY (5-gate policy engine) ────────────────

@app.post("/v1/verify", tags=["Operational Gateway"])
async def gate_verify(
    req: VerifyRequest,
    request: Request,
    x_api_key: Optional[str] = Header(None)
):
    """
    OPERATIONAL GATEWAY — 5-gate policy engine.
    Returns ALLOW / DENY / REQUIRE_HUMAN_APPROVAL with full gate breakdown.
    """
    start_time = time_module.time()  # FIX
    require_api_key(x_api_key)

    gates   = {"identity": False, "issuer": False, "trust_score": False,
               "runtime_state": False, "policy": False}
    reasons = []

    passport = await db_get("passports", "agent_id", req.agent_id)
    if not passport:
        return _deny_gate_response(req.agent_id, "Agent not found in VeriSigil registry", gates, start_time)

    # Gate 1 — Identity
    sig_valid = verify_payload(
        {"agent_id": passport["agent_id"], "did": passport["did"],
         "issued_at": passport["issued_at"], "owner": passport["owner"],
         "issuer": "https://verisigilai.com"},
        passport.get("signature", ""))
    gates["identity"] = sig_valid
    if not sig_valid:
        reasons.append("Invalid cryptographic signature — possible forgery")

    # Gate 2 — Issuer
    issuer_org = passport.get("issuer_org") or passport.get("owner")
    gates["issuer"] = bool(issuer_org and issuer_org != "unknown")
    if not gates["issuer"]:
        reasons.append("Issuer not verified or unknown")

    # Gate 3 — Trust Score
    trust_score = float(passport.get("trust_score", 0.0))
    policy      = POLICY_THRESHOLDS.get(req.policy_mode, POLICY_THRESHOLDS["standard"])
    min_trust   = policy["min_trust_score"]
    gates["trust_score"] = trust_score >= min_trust
    if not gates["trust_score"]:
        reasons.append(f"Trust score {trust_score:.2f} below threshold {min_trust}")

    # Gate 4 — Runtime State
    is_revoked = passport.get("status") == "REVOKED"
    is_expired = datetime.utcnow() > datetime.fromisoformat(passport["expires_at"])
    gates["runtime_state"] = not (is_revoked or is_expired)
    if is_revoked: reasons.append("Agent passport revoked")
    if is_expired: reasons.append("Agent passport expired")

    # Gate 5 — Policy
    action_type    = req.action_type.lower()
    requires_human = action_type in policy.get("require_human_for", [])
    if action_type in ["transfer", "payment"] and "amount" in req.action_detail.lower():
        amounts = re.findall(r'\$?(\d+(?:,\d+)*(?:\.\d+)?)', req.action_detail)
        if amounts:
            amount = float(amounts[0].replace(',', ''))
            if amount > policy["max_amount_usd"]:
                requires_human = True
                reasons.append(f"Amount ${amount:,.2f} exceeds {req.policy_mode} threshold")
    gates["policy"] = not requires_human
    if requires_human:
        reasons.append(f"Action '{action_type}' requires human approval")

    # Final Decision
    all_passed = all(gates.values())
    if all_passed:
        decision = GateDecision.ALLOW
    elif requires_human:
        decision = GateDecision.REQUIRE_HUMAN_APPROVAL
    else:
        decision = GateDecision.DENY

    audit_id  = f"evt_{uuid.uuid4().hex[:8]}"
    timestamp = datetime.utcnow().isoformat()
    latency   = round((time_module.time() - start_time) * 1000, 2)  # FIX

    await log_event(req.agent_id, "GATE_VERIFY", {
        "audit_id": audit_id, "action_type": req.action_type,
        "policy_mode": req.policy_mode, "decision": decision.value,
        "gates": gates, "trust_score": trust_score, "latency_ms": latency,
        "caller_ip": request.client.host if request.client else "unknown"})

    return VerifyResponse(
        decision=decision, gates=gates, trust_score=trust_score,
        latency_ms=latency, audit_id=audit_id, eu_act_compliant=True,
        reason=" | ".join(reasons) if reasons else None)

@app.get("/v1/guard/sdk", tags=["Runtime Guard"])
async def get_sdk_integration(x_api_key: Optional[str] = Header(None)):
    require_api_key(x_api_key)
    return {
        "sdk_snippet": '''
# VeriSigil Runtime Guard — 15-minute integration
import requests, os

class VeriSigilGuard:
    def __init__(self, agent_id: str, api_key: str):
        self.agent_id = agent_id
        self.session  = requests.Session()
        self.session.headers.update({"x-api-key": api_key, "Content-Type": "application/json"})

    def verify_before_execution(self, action_type: str, action_details: dict, resource: str):
        resp   = self.session.post(
            "https://verisigil-api-production.up.railway.app/v1/guard/verify",
            json={"agent_id": self.agent_id, "action_type": action_type,
                  "action_details": action_details, "resource": resource})
        result = resp.json()
        if result["decision"] == "DENY":
            raise PermissionError(f"Blocked: {result['reason']}")
        return result["decision"] == "ALLOW"
''',
        "integration_time": "15 minutes",
        "docs": "https://verisigil-api-production.up.railway.app/docs#/Runtime%20Guard"
    }

# ============================================================
# v0.5.3 — COMPLIANCE SPRINT
# ============================================================
# ============================================================
# v0.5.3 — COMPLIANCE SPRINT AUTOMATION
# POST /v1/sprint/run
# Automatically issues passport + sends compliance email
# ============================================================

class SprintRequest(BaseModel):
    # Customer details
    customer_name:    str
    customer_email:   str
    company_name:     str
    website:          Optional[str] = None
    # Agent details
    agent_name:       str
    agent_description: str
    industry:         str  # fintech, healthcare, legal, hr, enterprise, other
    framework:        str = "unknown"
    eu_users:         bool = True
    # Contact
    linkedin:         Optional[str] = None

class SprintResponse(BaseModel):
    success:          bool
    sprint_id:        str
    agent_id:         str
    passport_did:     str
    trust_score:      float
    eu_risk_class:    str
    compliance_url:   str
    email_sent:       bool
    message:          str

def classify_eu_risk(industry: str, agent_description: str) -> str:
    """Classify EU AI Act risk level based on industry and description."""
    high_risk_industries = ["fintech", "healthcare", "legal", "hr", "education", "biometrics", "law_enforcement"]
    high_risk_keywords   = ["payment", "credit", "medical", "patient", "hiring", "recruitment",
                             "scoring", "diagnosis", "loan", "insurance", "border", "police"]
    
    industry_lower     = industry.lower()
    description_lower  = agent_description.lower()
    
    if industry_lower in high_risk_industries:
        return "HIGH_RISK"
    
    for kw in high_risk_keywords:
        if kw in description_lower:
            return "HIGH_RISK"
    
    return "LIMITED_RISK"

async def send_compliance_email(
    customer_email:  str,
    customer_name:   str,
    company_name:    str,
    agent_name:      str,
    agent_id:        str,
    passport_did:    str,
    eu_risk_class:   str,
    sprint_id:       str,
    compliance_url:  str,
    resend_api_key:  str
) -> bool:
    """
    Send compliance sprint email via Supabase Edge Function (resend-email).
    Edge Functions call Resend HTTP API directly — no network restrictions.
    """
    supabase_url = os.environ.get("SUPABASE_URL", "")
    supabase_key = os.environ.get("SUPABASE_SERVICE_KEY", os.environ.get("SUPABASE_KEY", ""))
    edge_url     = f"{supabase_url}/functions/v1/resend-email"

    risk_color = "#EF4444" if eu_risk_class == "HIGH_RISK" else "#F59E0B"
    risk_label = "HIGH RISK" if eu_risk_class == "HIGH_RISK" else "LIMITED RISK"

    html_body = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<style>
body{{font-family:'Segoe UI',Arial,sans-serif;background:#050E2B;color:#fff;margin:0;padding:0}}
.wrap{{max-width:600px;margin:0 auto;padding:32px 20px}}
.logo{{font-size:20px;font-weight:800;color:#00D4F5;margin-bottom:24px}}
.hero{{background:linear-gradient(135deg,#0D1A3A,#0A1628);border:1px solid rgba(0,212,245,0.2);border-radius:14px;padding:28px;margin-bottom:20px;text-align:center}}
.hero h1{{font-size:22px;font-weight:700;margin-bottom:8px}}
.hero p{{color:#94A3B8;font-size:14px;margin:0}}
.box{{background:#0D1A3A;border:1px solid rgba(30,58,110,0.6);border-radius:12px;padding:20px;margin-bottom:14px}}
.bt{{font-size:12px;font-weight:700;color:#00D4F5;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:14px}}
.row{{padding:8px 0;border-bottom:1px solid rgba(30,58,110,0.4);font-size:13px}}
.row:last-child{{border-bottom:none}}
.rl{{color:#94A3B8;margin-bottom:3px;font-size:11px;text-transform:uppercase;letter-spacing:0.05em}}
.rv{{color:#fff;font-family:monospace;word-break:break-all}}
.badge{{display:inline-block;background:{risk_color}22;border:1px solid {risk_color}44;color:{risk_color};font-size:10px;font-weight:700;padding:3px 10px;border-radius:20px}}
.cl{{list-style:none;padding:0;margin:0}}
.cl li{{display:flex;align-items:center;gap:10px;font-size:13px;color:#94A3B8;padding:7px 0;border-bottom:1px solid rgba(30,58,110,0.3)}}
.cl li:last-child{{border-bottom:none}}
.chk{{color:#22C55E;font-size:16px;flex-shrink:0}}
.cta{{display:block;background:#00D4F5;color:#050E2B;text-align:center;padding:14px;border-radius:9px;font-weight:800;font-size:15px;text-decoration:none;margin:16px 0}}
.code{{background:#020812;border:1px solid rgba(30,58,110,0.6);border-radius:7px;padding:14px;font-family:monospace;font-size:11px;color:#00D4F5;word-break:break-all;line-height:1.6}}
.footer{{text-align:center;font-size:11px;color:#475569;margin-top:28px;padding-top:20px;border-top:1px solid rgba(30,58,110,0.4)}}
.footer a{{color:#00D4F5;text-decoration:none}}
</style></head><body><div class="wrap">
<div class="logo">⬡ VeriSigil AI</div>
<div class="hero">
  <h1>🎉 Your Compliance Sprint Is Ready</h1>
  <p>Your AI agent now has cryptographic identity, Runtime Guard governance,<br>and EU AI Act compliance documentation — all live right now.</p>
</div>
<div class="box">
  <div class="bt">🔐 Your Agent Passport</div>
  <div class="row"><div class="rl">Agent Name</div><div class="rv">{agent_name}</div></div>
  <div class="row"><div class="rl">Agent ID</div><div class="rv">{agent_id}</div></div>
  <div class="row"><div class="rl">Decentralised Identity (DID)</div><div class="rv">{passport_did}</div></div>
  <div class="row"><div class="rl">EU Risk Classification</div><div class="rv"><span class="badge">{risk_label}</span></div></div>
  <div class="row"><div class="rl">Company</div><div class="rv">{company_name}</div></div>
  <div class="row"><div class="rl">Sprint Reference</div><div class="rv">{sprint_id}</div></div>
  <div class="row"><div class="rl">Issued By</div><div class="rv">VeriSigil AI · verisigilai.com</div></div>
</div>
<div class="box">
  <div class="bt">✅ What Is Now Active</div>
  <ul class="cl">
    <li><span class="chk">✓</span> Cryptographic passport — Ed25519 signed, W3C DID standard</li>
    <li><span class="chk">✓</span> Runtime Guard — every action verified before execution</li>
    <li><span class="chk">✓</span> Immutable audit trail — every event cryptographically logged</li>
    <li><span class="chk">✓</span> Shadow Detection™ — real-time clone monitoring active</li>
    <li><span class="chk">✓</span> EU AI Act transparency — Article 50 compliant</li>
    <li><span class="chk">✓</span> Human oversight enforcement — Article 14 compliant</li>
  </ul>
</div>
<div class="box">
  <div class="bt">📋 Your Compliance Report</div>
  <p style="font-size:13px;color:#94A3B8;margin-bottom:12px">View, download as PDF, and share with regulators or enterprise buyers:</p>
  <a href="{compliance_url}" class="cta">📋 View Full Compliance Report →</a>
</div>
<div class="box">
  <div class="bt">⚡ Add Runtime Guard — 3 Lines</div>
  <div class="code">import requests, os

def verify_before_execution(action_type, details, resource):
    r = requests.post(
        "https://verisigil-api-production.up.railway.app/v1/guard/verify",
        headers={{"x-api-key": os.getenv("VERISIGIL_API_KEY")}},
        json={{"agent_id":"{agent_id}","action_type":action_type,
              "action_details":details,"resource":resource}}
    ).json()
    if r["decision"]=="DENY": raise PermissionError(r["reason"])
    return r["decision"]</div>
  <p style="font-size:11px;color:#94A3B8;margin-top:10px">Full SDK: <a href="https://verisigilai.com/sdk.html" style="color:#00D4F5">verisigilai.com/sdk.html</a></p>
</div>
<div class="box">
  <div class="bt">🔍 Public Verification URL</div>
  <div class="code">https://verisigil-api-production.up.railway.app/verify/{agent_id}</div>
  <p style="font-size:11px;color:#94A3B8;margin-top:8px">Share with regulators, enterprise buyers, or partners as cryptographic proof of your agent's identity.</p>
</div>
<div class="footer">
  <p>Questions? Reply to this email — Raheem reads every message personally.</p>
  <p style="margin-top:6px"><a href="mailto:raheem@verisigilai.com">raheem@verisigilai.com</a></p>
  <p style="margin-top:6px">Built by <strong>Raheem Larry Babatunde</strong> · Lagos, Nigeria 🇳🇬</p>
  <p style="margin-top:8px"><a href="https://verisigilai.com">verisigilai.com</a></p>
</div>
</div></body></html>"""

    try:
        async with httpx.AsyncClient() as c:
            r = await c.post(
                edge_url,
                headers={
                    "Authorization": f"Bearer {supabase_key}",
                    "Content-Type":  "application/json",
                },
                json={
                    "to":      customer_email,
                    "subject": f"✅ Your VeriSigil Compliance Sprint Is Ready — {agent_name}",
                    "html":    html_body,
                    "from":    "VeriSigil AI <raheem@verisigilai.com>",
                },
                timeout=20
            )
            result = r.json()
            if r.status_code == 200 and result.get("id"):
                print(f"[SPRINT EMAIL] ✅ Sent to {customer_email} | ID: {result.get('id')}")
                return True
            else:
                print(f"[SPRINT EMAIL ERROR] Edge Function returned {r.status_code}: {result}")
                return False
    except Exception as e:
        print(f"[SPRINT EMAIL ERROR] {e}")
        return False




@app.post("/v1/sprint/run", tags=["Compliance Sprint"])
async def run_compliance_sprint(
    req: SprintRequest,
    x_api_key: Optional[str] = Header(None)
):
    """
    COMPLIANCE SPRINT — Fully Automatic
    Issues passport + sends compliance email in one call.
    Public endpoint — customers trigger this from Sigil Studio.
    """
    require_api_key(x_api_key)

    sprint_id    = f"sprint_{uuid.uuid4().hex[:10].upper()}"
    eu_risk_class = classify_eu_risk(req.industry, req.agent_description)

    # 1. Issue passport automatically
    p = make_passport(
        agent_name   = req.agent_name,
        owner        = req.customer_email,
        framework    = req.framework,
        runtime      = "python",
        version      = "1.0.0",
        tags         = ["compliance_sprint", req.industry, sprint_id],
        expiry_days  = 365,
        display_name = req.agent_name,
        issuer_org   = req.company_name,
    )

    # Override risk class based on classification
    p["eu_risk_class"] = eu_risk_class

    # 2. Store passport in database
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
        "eu_risk_class":     eu_risk_class,
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
        await db_insert("passports", db_record)
        stored = True
    except Exception as e:
        stored = False
        print(f"[SPRINT DB ERROR] {e}")

    # 3. Store sprint record in waitlist table for tracking
    try:
        await db_insert("waitlist", {
            "email":    req.customer_email,
            "name":     req.customer_name,
            "company":  req.company_name,
            "use_case": f"Sprint: {req.agent_name} | Industry: {req.industry} | Risk: {eu_risk_class}",
            "tier":     "sprint_499",
            "source":   "compliance_sprint",
            "status":   "active"
        })
    except Exception as e:
        print(f"[SPRINT WAITLIST ERROR] {e}")

    # 4. Build compliance report URL
    compliance_url = f"https://verisigilai.com/compliance-report.html?agent_id={p['agent_id']}&sprint_id={sprint_id}"

    # 5. Send email via Supabase Edge Function
    resend_key = os.environ.get("RESEND_API_KEY", "")
    email_sent = False
    try:
        email_sent = await send_compliance_email(
            customer_email  = req.customer_email,
            customer_name   = req.customer_name,
            company_name    = req.company_name,
            agent_name      = req.agent_name,
            agent_id        = p["agent_id"],
            passport_did    = p["did"],
            eu_risk_class   = eu_risk_class,
            sprint_id       = sprint_id,
            compliance_url  = compliance_url,
            resend_api_key  = resend_key
        )
    except Exception as e:
        print(f"[SPRINT EMAIL ERROR] {e}")

    # 6. Log the sprint event
    await log_event(p["agent_id"], "SPRINT_COMPLETED", {
        "sprint_id":     sprint_id,
        "customer_email": req.customer_email,
        "company":       req.company_name,
        "industry":      req.industry,
        "eu_risk_class": eu_risk_class,
        "email_sent":    email_sent,
        "stored":        stored,
    })

    return SprintResponse(
        success        = stored,
        sprint_id      = sprint_id,
        agent_id       = p["agent_id"],
        passport_did   = p["did"],
        trust_score    = p["trust_score"],
        eu_risk_class  = eu_risk_class,
        compliance_url = compliance_url,
        email_sent     = email_sent,
        message        = f"Sprint complete! Passport issued and compliance email sent to {req.customer_email}. Check your inbox."
    )




async def send_approval_email(
    approver_email: str,
    agent_name:     str,
    agent_id:       str,
    action_type:    str,
    action_details: dict,
    reason:         str,
    trust_score:    float,
    approval_id:    str,
    approval_url:   str,
    execution_id:   str
) -> bool:
    """Send approval notification email via Supabase Edge Function."""
    supabase_url = os.environ.get("SUPABASE_URL", "")
    supabase_key = os.environ.get("SUPABASE_SERVICE_KEY", os.environ.get("SUPABASE_KEY", ""))
    edge_url     = f"{supabase_url}/functions/v1/resend-email"

    amount = action_details.get("amount_usd")
    amount_str = f"${float(amount):,.2f} USD" if amount else ""

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<style>
body{{font-family:'Segoe UI',Arial,sans-serif;background:#050E2B;color:#fff;margin:0;padding:0}}
.wrap{{max-width:560px;margin:0 auto;padding:28px 20px}}
.logo{{font-size:18px;font-weight:800;color:#00D4F5;margin-bottom:20px}}
.hero{{background:rgba(245,158,11,0.08);border:1px solid rgba(245,158,11,0.25);border-radius:12px;padding:24px;margin-bottom:18px;text-align:center}}
.hero-icon{{font-size:36px;margin-bottom:10px}}
.hero-title{{font-size:18px;font-weight:700;color:#F59E0B;margin-bottom:6px}}
.hero-sub{{font-size:13px;color:#94A3B8}}
.box{{background:#0D1A3A;border:1px solid rgba(30,58,110,0.6);border-radius:10px;padding:18px;margin-bottom:14px}}
.box-title{{font-size:11px;font-weight:700;color:#00D4F5;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:12px}}
.row{{display:flex;justify-content:space-between;padding:7px 0;border-bottom:1px solid rgba(30,58,110,0.4);font-size:13px}}
.row:last-child{{border-bottom:none}}
.label{{color:#94A3B8}}.value{{color:#fff;font-family:monospace;font-size:12px;text-align:right;word-break:break-all;max-width:280px}}
.amount{{color:#F59E0B;font-size:15px;font-weight:700}}
.reason-box{{background:rgba(245,158,11,0.06);border:1px solid rgba(245,158,11,0.2);border-radius:8px;padding:12px 14px;margin-bottom:14px}}
.reason-text{{color:#F59E0B;font-size:13px;font-weight:600}}
.cta{{display:block;background:#00D4F5;color:#050E2B;text-align:center;padding:14px;border-radius:9px;font-weight:800;font-size:15px;text-decoration:none;margin:18px 0}}
.note{{font-size:11px;color:#94A3B8;text-align:center;margin-bottom:14px}}
.footer{{text-align:center;font-size:11px;color:#475569;margin-top:20px;padding-top:16px;border-top:1px solid rgba(30,58,110,0.4)}}
.footer a{{color:#00D4F5;text-decoration:none}}
</style></head><body><div class="wrap">
<div class="logo">⬡ VeriSigil AI</div>
<div class="hero">
  <div class="hero-icon">⚠️</div>
  <div class="hero-title">Action Requires Your Approval</div>
  <div class="hero-sub">An AI agent is requesting to perform a high-risk action.<br>Your approval is required before it can proceed.</div>
</div>
<div class="box">
  <div class="box-title">🤖 Agent Identity</div>
  <div class="row"><span class="label">Agent Name</span><span class="value">{agent_name}</span></div>
  <div class="row"><span class="label">Agent ID</span><span class="value">{agent_id}</span></div>
  <div class="row"><span class="label">Trust Score</span><span class="value">{trust_score}</span></div>
</div>
<div class="box">
  <div class="box-title">⚡ Requested Action</div>
  <div class="row"><span class="label">Action Type</span><span class="value">{action_type}</span></div>
  {f'<div class="row"><span class="label">Amount</span><span class="value amount">{amount_str}</span></div>' if amount_str else ''}
  <div class="row"><span class="label">Execution ID</span><span class="value">{execution_id}</span></div>
</div>
<div class="reason-box">
  <div style="font-size:11px;color:#94A3B8;margin-bottom:4px;text-transform:uppercase;letter-spacing:0.08em">Why This Needs Approval</div>
  <div class="reason-text">⚡ {reason}</div>
</div>
<a href="{approval_url}" class="cta">Review and Approve or Reject →</a>
<div class="note">This approval request expires in 24 hours.<br>Approval ID: {approval_id}</div>
<div class="footer">
  <p>Powered by <a href="https://verisigilai.com">VeriSigil AI</a> — Runtime Governance for Autonomous AI Agents</p>
  <p style="margin-top:4px"><a href="mailto:raheem@verisigilai.com">raheem@verisigilai.com</a></p>
</div>
</div></body></html>"""

    try:
        async with httpx.AsyncClient() as c:
            r = await c.post(
                edge_url,
                headers={
                    "Authorization": f"Bearer {supabase_key}",
                    "Content-Type":  "application/json",
                },
                json={
                    "to":      approver_email,
                    "subject": f"⚠️ Approval Required — {agent_name} is requesting a {action_type} action",
                    "html":    html,
                    "from":    "VeriSigil AI <raheem@verisigilai.com>",
                },
                timeout=15
            )
            result = r.json()
            if r.status_code == 200 and result.get("id"):
                print(f"[APPROVAL EMAIL] ✅ Sent to {approver_email}")
                return True
            else:
                print(f"[APPROVAL EMAIL ERROR] {r.status_code}: {result}")
                return False
    except Exception as e:
        print(f"[APPROVAL EMAIL ERROR] {e}")
        return False


# ============================================================
# v0.5.4 — APPROVAL CONSOLE
# Human-in-the-loop for Runtime Guard REQUIRE_HUMAN_APPROVAL
# ============================================================

class ApprovalCreate(BaseModel):
    execution_id:   str
    agent_id:       str
    action_type:    str
    action_details: dict = {}
    resource:       str
    trust_score:    float
    reason:         str
    approver_email: Optional[str] = None

class ApprovalDecision(BaseModel):
    decision:       str  # "approved" or "rejected"
    approver_name:  str
    approver_email: str
    reason:         Optional[str] = None

@app.post("/v1/approvals/create", tags=["Approval Console"])
async def create_approval(
    req: ApprovalCreate,
    x_api_key: Optional[str] = Header(None)
):
    """
    Create a human approval request.
    Called automatically when Runtime Guard returns REQUIRE_HUMAN_APPROVAL.
    """
    require_api_key(x_api_key)

    approval_id = f"apr_{uuid.uuid4().hex[:8]}"
    expires_at  = (datetime.utcnow() + timedelta(hours=24)).isoformat()
    created_at  = datetime.utcnow().isoformat()
    review_url  = f"https://verisigilai.com/approve.html?id={approval_id}"

    record = {
        "id":             approval_id,
        "execution_id":   req.execution_id,
        "agent_id":       req.agent_id,
        "action_type":    req.action_type,
        "action_details": req.action_details,
        "resource":       req.resource,
        "trust_score":    req.trust_score,
        "reason":         req.reason,
        "status":         "pending",
        "approver_email": req.approver_email,
        "expires_at":     expires_at,
        "created_at":     created_at,
    }

    try:
        await db_insert("approval_requests", record)
        stored = True
    except Exception as e:
        stored = False
        print(f"[APPROVAL CREATE ERROR] {e}")

    await log_event(req.agent_id, "APPROVAL_CREATED", {
        "approval_id":  approval_id,
        "execution_id": req.execution_id,
        "action_type":  req.action_type,
        "reason":       req.reason,
        "review_url":   review_url,
    })

    return {
        "success":     stored,
        "approval_id": approval_id,
        "status":      "pending",
        "review_url":  review_url,
        "expires_at":  expires_at,
        "message":     f"Approval request created. Review at: {review_url}"
    }


@app.get("/v1/approvals/{approval_id}", tags=["Approval Console"])
async def get_approval(approval_id: str):
    """
    Public endpoint — approver loads this to see the request details.
    No API key required so the approver can view without credentials.
    """
    # Use service key to bypass RLS for approval lookup
    async with httpx.AsyncClient() as _c:
        _r = await _c.get(
            f"{SUPABASE_URL}/rest/v1/approval_requests?id=eq.{approval_id}",
            headers=get_headers(write=True), timeout=10
        )
        _rows = _r.json() if _r.status_code == 200 else []
        approval = _rows[0] if isinstance(_rows, list) and _rows else None
    if not approval:
        raise HTTPException(404, "Approval request not found.")

    # Get agent details
    agent = await db_get("passports", "agent_id", approval["agent_id"])

    # Check expiry
    is_expired = False
    try:
        is_expired = datetime.utcnow() > datetime.fromisoformat(
            approval["expires_at"].replace("Z", ""))
    except Exception:
        pass

    if is_expired and approval["status"] == "pending":
        await db_patch("approval_requests", "id", approval_id, {"status": "expired"})
        approval["status"] = "expired"

    return {
        "approval_id": approval_id,
        "status":      approval["status"],
        "agent": {
            "agent_id":     agent["agent_id"]      if agent else "unknown",
            "display_name": agent.get("display_name","Unknown") if agent else "Unknown",
            "issuer_org":   agent.get("issuer_org", "Unknown") if agent else "Unknown",
            "trust_score":  agent.get("trust_score", 0)        if agent else 0,
        },
        "action": {
            "type":    approval["action_type"],
            "details": approval["action_details"],
            "resource": approval["resource"],
        },
        "policy_trigger":         approval["reason"],
        "trust_score_at_decision": approval["trust_score"],
        "created_at":  approval["created_at"],
        "expires_at":  approval["expires_at"],
        "is_expired":  is_expired,
        "decision_at": approval.get("approved_at"),
        "decision_by": approval.get("approver_name") or approval.get("approver_email"),
        "rejection_reason": approval.get("rejection_reason"),
    }


@app.post("/v1/approvals/{approval_id}/decide", tags=["Approval Console"])
async def decide_approval(approval_id: str, req: ApprovalDecision):
    """
    Approver submits APPROVE or REJECT decision.
    No API key required — approver uses the review URL directly.
    """
    if req.decision not in ["approved", "rejected"]:
        raise HTTPException(400, "Decision must be 'approved' or 'rejected'.")

    approval = await db_get("approval_requests", "id", approval_id)
    if not approval:
        raise HTTPException(404, "Approval request not found.")

    if approval["status"] != "pending":
        raise HTTPException(400, f"This request has already been {approval['status']}.")

    # Check expiry
    try:
        is_expired = datetime.utcnow() > datetime.fromisoformat(
            approval["expires_at"].replace("Z", ""))
        if is_expired:
            await db_patch("approval_requests", "id", approval_id, {"status": "expired"})
            raise HTTPException(400, "This approval request has expired.")
    except HTTPException:
        raise
    except Exception:
        pass

    if req.decision == "rejected" and not req.reason:
        raise HTTPException(400, "A reason is required when rejecting an action.")

    update = {
        "status":         req.decision,
        "approver_name":  req.approver_name,
        "approver_email": req.approver_email,
        "approved_at":    datetime.utcnow().isoformat(),
    }
    if req.decision == "rejected":
        update["rejection_reason"] = req.reason

    await db_patch("approval_requests", "id", approval_id, update)

    await log_event(approval["agent_id"], "APPROVAL_DECIDED", {
        "approval_id":  approval_id,
        "execution_id": approval["execution_id"],
        "decision":     req.decision,
        "approver":     req.approver_name,
        "reason":       req.reason,
    })

    return {
        "approval_id": approval_id,
        "status":      req.decision,
        "agent_id":    approval["agent_id"],
        "decided_by":  req.approver_name,
        "message":     f"Action {req.decision} by {req.approver_name}. Decision cryptographically logged."
    }


@app.get("/v1/approvals", tags=["Approval Console"])
async def list_approvals(
    status: Optional[str] = None,
    agent_id: Optional[str] = None,
    x_api_key: Optional[str] = Header(None)
):
    """List approval requests. Filter by status or agent_id."""
    require_api_key(x_api_key)

    url = f"{SUPABASE_URL}/rest/v1/approval_requests?order=created_at.desc&limit=50"
    if status:
        url += f"&status=eq.{status}"
    if agent_id:
        url += f"&agent_id=eq.{agent_id}"

    async with httpx.AsyncClient() as c:
        r = await c.get(url, headers=get_headers(write=False), timeout=10)
        approvals = r.json() if r.status_code == 200 else []

    return {
        "total":     len(approvals),
        "approvals": approvals,
        "filter":    {"status": status, "agent_id": agent_id}
    }


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), reload=False)
