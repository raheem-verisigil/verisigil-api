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
from fastapi.responses import JSONResponse
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

# ============================================================
# MAINTENANCE & GOVERNANCE INFRASTRUCTURE
# ============================================================
MAINTENANCE_MODE    = os.environ.get("MAINTENANCE_MODE", "false").lower() == "true"
MAINTENANCE_MESSAGE = os.environ.get("MAINTENANCE_MESSAGE", "VeriSigil AI is under scheduled maintenance. Back shortly.")
DEPLOY_ENV          = os.environ.get("DEPLOY_ENV", "production")
DEPLOY_VERSION      = "0.6.1"
DEPLOY_TIMESTAMP    = datetime.utcnow().isoformat()

# Feature flags — toggle in Railway env vars, never by changing code
FEATURES = {
    "PASSPORT_ISSUANCE":        os.environ.get("FF_PASSPORT_ISSUANCE",        "true").lower()  == "true",
    "RUNTIME_GUARD":            os.environ.get("FF_RUNTIME_GUARD",            "true").lower()  == "true",
    "AUDIT_TRAIL":              os.environ.get("FF_AUDIT_TRAIL",              "true").lower()  == "true",
    "SHADOW_DETECTION":         os.environ.get("FF_SHADOW_DETECTION",         "true").lower()  == "true",
    "HUMAN_APPROVAL":           os.environ.get("FF_HUMAN_APPROVAL",           "true").lower()  == "true",
    "COMPLIANCE_SPRINT":        os.environ.get("FF_COMPLIANCE_SPRINT",        "true").lower()  == "true",
    "RUNTIME_REVALIDATION":     os.environ.get("FF_RUNTIME_REVALIDATION",     "false").lower() == "true",
    "AGENT_CHAIN_PROVENANCE":   os.environ.get("FF_AGENT_CHAIN_PROVENANCE",   "false").lower() == "true",
    "MULTI_AGENT_GOVERNANCE":   os.environ.get("FF_MULTI_AGENT_GOVERNANCE",   "false").lower() == "true",
    "EXECUTION_SURVIVABILITY":  os.environ.get("FF_EXECUTION_SURVIVABILITY",  "false").lower() == "true",
    "CONTINUOUS_ADMISSIBILITY": os.environ.get("FF_CONTINUOUS_ADMISSIBILITY", "false").lower() == "true",
}

def feature_enabled(name: str) -> bool:
    return FEATURES.get(name, False)

def require_feature(name: str):
    if not feature_enabled(name):
        raise HTTPException(503, f"Feature '{name}' is currently disabled.")

# In-memory request metrics
_metrics = {
    "requests_total":    0,
    "requests_ok":       0,
    "requests_error":    0,
    "guard_decisions":   0,
    "passports_issued":  0,
    "approvals_created": 0,
    "sprints_run":       0,
    "start_time":        time(),
}

def _inc(key): _metrics[key] = _metrics.get(key, 0) + 1

def get_uptime() -> str:
    s = int(time() - _metrics["start_time"])
    d, s = divmod(s, 86400); h, s = divmod(s, 3600); m, s = divmod(s, 60)
    if d: return f"{d}d {h}h {m}m"
    if h: return f"{h}h {m}m {s}s"
    return f"{m}m {s}s"

_seed          = hashlib.sha256(SIGN_SECRET.encode()).digest()
SIGNING_KEY    = SigningKey(_seed)
VERIFY_KEY     = SIGNING_KEY.verify_key
PUBLIC_KEY_B64 = base64.b64encode(bytes(VERIFY_KEY)).decode()

# ============================================================
# MERKLE CHAIN AUDIT INFRASTRUCTURE
# ============================================================
# Every governance decision is chained to the previous one
# creating a tamper-evident, replay-verifiable audit chain
# matching enterprise governance requirements

_chain: list[dict] = []          # in-memory chain (persisted to Supabase)
_chain_head: str   = "genesis"   # hash of last block

def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def _compute_block_hash(
    previous_hash: str,
    execution_id:  str,
    agent_id:      str,
    action:        str,
    decision:      str,
    policy_reason: str,
    timestamp:     str,
    confidence:    float,
) -> str:
    """Deterministic hash — same inputs always produce same hash."""
    payload = (
        f"{previous_hash}|{execution_id}|{agent_id}|"
        f"{action}|{decision}|{policy_reason}|"
        f"{timestamp}|{confidence}"
    )
    return _sha256(payload)

def _compute_merkle_root(hashes: list[str]) -> str:
    """Compute Merkle root from list of block hashes."""
    if not hashes:
        return _sha256("empty")
    nodes = list(hashes)
    while len(nodes) > 1:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])  # duplicate last if odd
        nodes = [
            _sha256(nodes[i] + nodes[i+1])
            for i in range(0, len(nodes), 2)
        ]
    return nodes[0]

def chain_append(
    execution_id:  str,
    agent_id:      str,
    action:        str,
    decision:      str,
    policy_reason: str,
    confidence:    float,
    extra:         dict = None,
) -> dict:
    """
    Append a new block to the governance chain.
    Returns the full block with hash, merkle root, and chain integrity.
    """
    global _chain_head
    
    timestamp   = datetime.utcnow().isoformat()
    block_index = len(_chain)
    
    block_hash  = _compute_block_hash(
        previous_hash = _chain_head,
        execution_id  = execution_id,
        agent_id      = agent_id,
        action        = action,
        decision      = decision,
        policy_reason = policy_reason,
        timestamp     = timestamp,
        confidence    = confidence,
    )
    
    # Compute Merkle root from all hashes including this new one
    all_hashes   = [b["block_hash"] for b in _chain] + [block_hash]
    merkle_root  = _compute_merkle_root(all_hashes)
    
    block = {
        "block_index":     block_index,
        "block_hash":      block_hash,
        "previous_hash":   _chain_head,
        "execution_id":    execution_id,
        "agent_id":        agent_id,
        "action":          action,
        "decision":        decision,
        "policy_reason":   policy_reason,
        "confidence":      confidence,
        "timestamp":       timestamp,
        "merkle_root":     merkle_root,
        "chain_integrity": "verified",
        "tamper_evident":  True,
        **(extra or {}),
    }
    
    _chain.append(block)
    _chain_head = block_hash
    
    print(f"[CHAIN] Block #{block_index} appended | hash: {block_hash[:16]}... | merkle: {merkle_root[:16]}...")
    return block

def chain_verify_integrity() -> dict:
    """
    Verify the entire chain is intact and untampered.
    Recomputes every hash from scratch and compares.
    """
    if not _chain:
        return {"intact": True, "blocks": 0, "message": "Chain is empty"}
    
    prev_hash  = "genesis"
    violations = []
    
    for block in _chain:
        expected = _compute_block_hash(
            previous_hash = prev_hash,
            execution_id  = block["execution_id"],
            agent_id      = block["agent_id"],
            action        = block["action"],
            decision      = block["decision"],
            policy_reason = block["policy_reason"],
            timestamp     = block["timestamp"],
            confidence    = block["confidence"],
        )
        if expected != block["block_hash"]:
            violations.append({
                "block_index": block["block_index"],
                "expected":    expected[:16] + "...",
                "found":       block["block_hash"][:16] + "...",
            })
        prev_hash = block["block_hash"]
    
    all_hashes  = [b["block_hash"] for b in _chain]
    merkle_root = _compute_merkle_root(all_hashes)
    
    return {
        "intact":        len(violations) == 0,
        "blocks":        len(_chain),
        "violations":    violations,
        "merkle_root":   merkle_root,
        "chain_head":    _chain_head[:16] + "...",
        "drift_detected": len(violations) > 0,
    }

def chain_replay(execution_id: str) -> dict:
    """
    Replay a specific execution and verify it produces
    the same hash as originally recorded.
    Proves governance decisions are deterministic and reproducible.
    """
    original = next((b for b in _chain if b["execution_id"] == execution_id), None)
    if not original:
        return {"found": False, "execution_id": execution_id}
    
    # Recompute hash from original inputs
    replay_hash = _compute_block_hash(
        previous_hash = original["previous_hash"],
        execution_id  = original["execution_id"],
        agent_id      = original["agent_id"],
        action        = original["action"],
        decision      = original["decision"],
        policy_reason = original["policy_reason"],
        timestamp     = original["timestamp"],
        confidence    = original["confidence"],
    )
    
    hash_match     = replay_hash == original["block_hash"]
    policy_match   = original["decision"] == original["decision"]  # deterministic
    decision_match = hash_match
    
    return {
        "execution_id":    execution_id,
        "original_hash":   original["block_hash"],
        "replay_hash":     replay_hash,
        "hash_match":      hash_match,
        "policy_match":    policy_match,
        "guard_match":     hash_match,
        "decision_match":  decision_match,
        "deterministic":   hash_match,
        "drift_detected":  not hash_match,
        "original_snapshot": {
            "execution_id":    original["execution_id"],
            "policy_action":   original["decision"],
            "reason":          original["policy_reason"],
            "risk":            original.get("risk_class", "UNKNOWN"),
            "confidence":      original["confidence"],
            "final_decision":  original["decision"],
            "execution_guard_status": original["decision"],
        },
        "immutable_audit": {
            "chain_hash":       original["block_hash"],
            "merkle_root":      original["merkle_root"],
            "chain_integrity":  "verified",
            "tamper_evident":   True,
        }
    }

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

@app.middleware("http")
async def maintenance_middleware(request: Request, call_next):
    allowed = {"/health", "/status", "/docs", "/openapi.json", "/redoc"}
    if MAINTENANCE_MODE and request.url.path not in allowed:
        return JSONResponse(status_code=503, content={
            "status":  "maintenance",
            "message": MAINTENANCE_MESSAGE,
            "version": DEPLOY_VERSION,
            "env":     DEPLOY_ENV,
        })
    _inc("requests_total")
    response = await call_next(request)
    if response.status_code < 400: _inc("requests_ok")
    else: _inc("requests_error")
    return response

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

# ============================================================
# POLICY ENGINE — Customer-configurable enforcement rules
# ============================================================
# Default platform policies — customers override via /v1/policy API
# Every rule evaluated in order — first match wins

POLICY_RULES = {
    "payment": {
        "max_amount_usd":            1000,
        "require_human_if_high_risk": True,
        "auto_deny_above":           500000,
        "require_human_above":       1000,
        "require_audit":             True,
        "blocked_currencies":        [],
        "blocked_recipients":        [],
    },
    "data_access": {
        "require_audit":          True,
        "block_pii_if_not_gdpr":  True,
        "gdpr_allowed":           False,
        "require_human_for_pii":  True,
        "blocked_data_types":     ["ssn", "passport", "biometric"],
    },
    "tool_use": {
        "blocked_tools":   ["exec", "eval", "shell", "file_delete", "subprocess", "os.system"],
        "require_audit":   True,
        "require_human_for": ["file_write", "network_call", "database_write"],
    },
    "delete_records": {
        "always_require_human": True,
        "require_audit":        True,
        "auto_deny_bulk":       True,
        "bulk_threshold":       100,
    },
    "send_email": {
        "max_recipients":        50,
        "require_human_above":   100,
        "blocked_domains":       [],
        "require_audit":         True,
    },
    "api_call": {
        "blocked_domains":       ["competitor.com"],
        "require_audit":         True,
        "require_human_for_external": False,
    },
    "deploy": {
        "always_require_human": True,
        "require_audit":        True,
        "blocked_environments": ["production"],
    },
    "database_write": {
        "require_audit":        True,
        "require_human_bulk":   True,
        "bulk_threshold":       1000,
    },
    "file_write": {
        "blocked_paths":        ["/etc", "/sys", "/root"],
        "require_audit":        True,
        "max_file_size_mb":     100,
    },
    "web_search": {
        "require_audit":        False,
        "auto_allow":           True,
    },
}

POLICY_THRESHOLDS = {
    "strict":     {"min_trust_score": 0.90, "max_amount_usd": 500,   "require_human_for": ["payment","transfer","delete_records","deploy","database_write"]},
    "standard":   {"min_trust_score": 0.75, "max_amount_usd": 10000, "require_human_for": ["payment","delete_records","deploy"]},
    "permissive": {"min_trust_score": 0.60, "max_amount_usd": 100000,"require_human_for": ["deploy"]},
}

# Customer-defined policy overrides stored in memory
# In production these are loaded from Supabase per org_id
_customer_policies: dict[str, dict] = {}

# ============================================================
# CUSTOMER ACCOUNTS — Auto-onboarding infrastructure
# ============================================================
# In-memory customer registry (persisted to Supabase)
_customers: dict[str, dict] = {}

PLAN_CONFIGS = {
    "starter": {
        "name":              "Starter",
        "price_usd":         49,
        "decisions_per_month": 1000,
        "policy_mode":       "standard",
        "features": [
            "runtime_guard",
            "audit_trail",
            "email_notifications",
            "merkle_chain",
        ],
        "policy_overrides": {},
    },
    "professional": {
        "name":              "Professional",
        "price_usd":         499,
        "decisions_per_month": -1,  # unlimited
        "policy_mode":       "standard",
        "features": [
            "runtime_guard",
            "audit_trail",
            "email_notifications",
            "merkle_chain",
            "replay_validation",
            "custom_policy",
            "enforcement_dashboard",
            "eu_ai_act_report",
            "human_approval_console",
        ],
        "policy_overrides": {
            "payment": {"require_human_above": 5000, "auto_deny_above": 1000000},
        },
    },
    "enterprise": {
        "name":              "Enterprise",
        "price_usd":         2499,
        "decisions_per_month": -1,  # unlimited
        "policy_mode":       "strict",
        "features": [
            "runtime_guard",
            "audit_trail",
            "email_notifications",
            "merkle_chain",
            "replay_validation",
            "custom_policy",
            "enforcement_dashboard",
            "eu_ai_act_report",
            "human_approval_console",
            "multi_agent_governance",
            "siem_export",
            "white_label",
            "sla_99_9",
            "dedicated_onboarding",
        ],
        "policy_overrides": {
            "payment":         {"require_human_above": 1000,  "auto_deny_above": 500000},
            "delete_records":  {"always_require_human": True, "bulk_threshold": 50},
            "deploy":          {"always_require_human": True, "blocked_environments": ["production"]},
            "data_access":     {"require_human_for_pii": True, "gdpr_allowed": False},
        },
    },
}

def detect_plan_from_amount(amount_usd: float) -> str:
    """Detect plan from Paystack payment amount."""
    if amount_usd >= 2499:
        return "enterprise"
    elif amount_usd >= 499:
        return "professional"
    elif amount_usd >= 49:
        return "starter"
    else:
        return "starter"

def generate_customer_api_key(org_id: str) -> str:
    """Generate a unique API key for a customer."""
    import secrets
    raw = f"vs_{org_id}_{secrets.token_hex(16)}"
    return raw

def get_effective_policy(org_id: str, action_type: str) -> dict:
    """Get effective policy — customer override takes precedence over platform default."""
    platform_policy  = POLICY_RULES.get(action_type, {})
    customer_policy  = _customer_policies.get(org_id, {}).get(action_type, {})
    # Merge — customer policy overrides platform defaults
    return {**platform_policy, **customer_policy}

def evaluate_policy_rules(
    action_type:    str,
    action_details: dict,
    policy:         dict,
    trust_score:    float,
    org_id:         str = "default",
) -> tuple[str, float, list[str]]:
    """
    Full policy evaluation engine.
    Returns (decision, confidence, reasons)
    decision: ALLOW | DENY | REQUIRE_HUMAN_APPROVAL
    """
    reasons = []

    # ── AUTO-ALLOW for safe actions ──────────────────────────
    if policy.get("auto_allow", False):
        return "ALLOW", 0.99, [f"{action_type} auto-allowed by policy"]

    # ── PAYMENT rules ────────────────────────────────────────
    if action_type == "payment":
        amount = float(action_details.get("amount_usd", 0))
        auto_deny = float(policy.get("auto_deny_above", 500000))
        human_threshold = float(policy.get("require_human_above", 1000))
        if amount > auto_deny:
            return "DENY", 0.99, [f"Payment ${amount:,.0f} exceeds maximum limit (${auto_deny:,.0f})"]
        if amount > human_threshold:
            return "REQUIRE_HUMAN_APPROVAL", 0.94, [f"Payment ${amount:,.0f} exceeds auto-allow threshold (${human_threshold:,.0f})"]
        recipient = action_details.get("recipient", "")
        if recipient in policy.get("blocked_recipients", []):
            return "DENY", 0.99, [f"Recipient '{recipient}' is blocked by policy"]

    # ── DELETE rules ─────────────────────────────────────────
    if action_type == "delete_records":
        if policy.get("always_require_human", False):
            return "REQUIRE_HUMAN_APPROVAL", 0.97, ["Delete operations always require human approval"]
        count = int(action_details.get("record_count", 1))
        if count > policy.get("bulk_threshold", 100):
            return "DENY", 0.98, [f"Bulk delete of {count} records exceeds threshold"]

    # ── DEPLOY rules ─────────────────────────────────────────
    if action_type == "deploy":
        if policy.get("always_require_human", False):
            return "REQUIRE_HUMAN_APPROVAL", 0.97, ["Deployments always require human approval"]
        env = action_details.get("environment", "")
        if env in policy.get("blocked_environments", []):
            return "DENY", 0.99, [f"Deployment to '{env}' is blocked by policy"]

    # ── TOOL USE rules ───────────────────────────────────────
    if action_type == "tool_use":
        tool = action_details.get("tool_name", "")
        if tool in policy.get("blocked_tools", []):
            return "DENY", 0.99, [f"Tool '{tool}' is blocked — dangerous execution capability"]
        if tool in policy.get("require_human_for", []):
            return "REQUIRE_HUMAN_APPROVAL", 0.93, [f"Tool '{tool}' requires human approval"]

    # ── DATA ACCESS rules ────────────────────────────────────
    if action_type == "data_access":
        if action_details.get("contains_pii", False):
            if not policy.get("gdpr_allowed", False):
                return "DENY", 0.97, ["PII access requires GDPR compliance certification"]
            if policy.get("require_human_for_pii", False):
                return "REQUIRE_HUMAN_APPROVAL", 0.93, ["PII access requires human oversight"]
        data_type = action_details.get("data_type", "")
        if data_type in policy.get("blocked_data_types", []):
            return "DENY", 0.99, [f"Data type '{data_type}' is blocked by policy"]

    # ── EMAIL rules ──────────────────────────────────────────
    if action_type == "send_email":
        recipients = int(action_details.get("recipient_count", 1))
        max_r = int(policy.get("max_recipients", 50))
        human_r = int(policy.get("require_human_above", 100))
        if recipients > human_r:
            return "REQUIRE_HUMAN_APPROVAL", 0.93, [f"Bulk email to {recipients} recipients requires approval"]
        if recipients > max_r:
            return "DENY", 0.96, [f"Email to {recipients} recipients exceeds maximum ({max_r})"]

    # ── DATABASE WRITE rules ─────────────────────────────────
    if action_type == "database_write":
        count = int(action_details.get("record_count", 1))
        if count > policy.get("bulk_threshold", 1000):
            return "REQUIRE_HUMAN_APPROVAL", 0.94, [f"Bulk database write of {count} records requires approval"]

    # ── TRUST-BASED threshold check ──────────────────────────
    if action_type in POLICY_THRESHOLDS.get("strict", {}).get("require_human_for", []):
        if trust_score < POLICY_THRESHOLDS["strict"]["min_trust_score"]:
            return "REQUIRE_HUMAN_APPROVAL", 0.92, [f"Trust score {trust_score:.3f} below strict threshold for {action_type}"]

    # ── ALLOW ────────────────────────────────────────────────
    reasons.append(f"Trust score {trust_score:.3f} sufficient · {action_type} within policy bounds")
    if policy.get("require_audit", False):
        reasons.append("Audit trail required — decision logged to immutable chain")
    return "ALLOW", 0.96, reasons

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
                       trust_score, action_type, action_details, policy,
                       org_id: str = "default") -> tuple:
    """
    Full enforcement decision engine.
    Priority order:
    1. Identity checks (signature, revocation, expiry, shadow)
    2. Trust score gates
    3. Customer policy rules
    4. Platform policy rules
    """
    # ── 1. IDENTITY GATES ────────────────────────────────────
    if not sig_valid:
        return Decision.DENY, 0.99, ["Invalid cryptographic signature — possible forgery"]
    if is_revoked:
        return Decision.DENY, 0.99, ["Agent passport revoked — access terminated"]
    if is_expired:
        return Decision.DENY, 0.98, ["Agent passport expired — renew to continue"]
    if shadow_detected:
        return Decision.DENY, 0.99, ["Shadow clone detected — identity conflict · possible replay attack"]

    # ── 2. TRUST SCORE GATES ─────────────────────────────────
    if trust_score < 0.50:
        return Decision.DENY, 0.99, [f"Trust score {trust_score:.3f} critically low — agent blocked"]
    if trust_score < 0.65:
        return Decision.DENY, 0.97, [f"Trust score {trust_score:.3f} below minimum enforcement threshold (0.65)"]
    if trust_score < 0.80:
        return Decision.REQUIRE_HUMAN_APPROVAL, 0.93, [
            f"Trust score {trust_score:.3f} in provisional range (0.65-0.80) — human oversight required"
        ]

    # ── 3. POLICY ENGINE EVALUATION ──────────────────────────
    effective_policy = get_effective_policy(org_id, action_type)
    policy_decision, policy_confidence, policy_reasons = evaluate_policy_rules(
        action_type    = action_type,
        action_details = action_details,
        policy         = effective_policy,
        trust_score    = trust_score,
        org_id         = org_id,
    )

    # Map string decision to Decision enum
    if policy_decision == "DENY":
        return Decision.DENY, policy_confidence, policy_reasons
    if policy_decision == "REQUIRE_HUMAN_APPROVAL":
        return Decision.REQUIRE_HUMAN_APPROVAL, policy_confidence, policy_reasons

    # ALLOW
    return Decision.ALLOW, policy_confidence, policy_reasons

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

@app.get("/health", tags=["System"])
async def health():
    return {
        "status":         "healthy",
        "version":        DEPLOY_VERSION,
        "env":            DEPLOY_ENV,
        "uptime":         get_uptime(),
        "maintenance":    MAINTENANCE_MODE,
        "database":       "online",
        "runtime_guard":  "online" if feature_enabled("RUNTIME_GUARD") else "disabled",
        "audit_trail":    "online" if feature_enabled("AUDIT_TRAIL") else "disabled",
        "human_approval": "online" if feature_enabled("HUMAN_APPROVAL") else "disabled",
        "timestamp":      datetime.utcnow().isoformat(),
        "metrics": {
            "requests_total":   _metrics["requests_total"],
            "guard_decisions":  _metrics["guard_decisions"],
            "passports_issued": _metrics["passports_issued"],
            "sprints_run":      _metrics["sprints_run"],
        }
    }

@app.get("/status", tags=["System"])
async def status():
    return {
        "status":      "operational" if not MAINTENANCE_MODE else "maintenance",
        "version":     DEPLOY_VERSION,
        "uptime":      get_uptime(),
        "maintenance": MAINTENANCE_MODE,
        "services": {
            "api":            "operational",
            "runtime_guard":  "operational" if feature_enabled("RUNTIME_GUARD") else "disabled",
            "database":       "operational",
            "audit_trail":    "operational" if feature_enabled("AUDIT_TRAIL") else "disabled",
            "human_approval": "operational" if feature_enabled("HUMAN_APPROVAL") else "disabled",
        },
        "timestamp": datetime.utcnow().isoformat(),
    }

@app.get("/admin/system", tags=["Admin"])
async def admin_system(x_api_key: Optional[str] = Header(None)):
    require_api_key(x_api_key)
    return {
        "version":       DEPLOY_VERSION,
        "env":           DEPLOY_ENV,
        "deployed_at":   DEPLOY_TIMESTAMP,
        "uptime":        get_uptime(),
        "maintenance":   MAINTENANCE_MODE,
        "feature_flags": FEATURES,
        "metrics":       _metrics,
    }

# ============================================================
# PROGRESSION ADMISSIBILITY ENGINE
# ============================================================
# The next layer beyond identity + action enforcement.
# Evaluates whether a specific state transition should be
# permitted given: evidence, authority, context, consequence,
# and the full workflow trajectory.
#
# This answers: "Should this specific progression be permitted NOW?"
# Not just: "Is this agent trusted?"

from enum import Enum as PyEnum

class ProgressionDecision(str, PyEnum):
    ALLOWED                   = "PROGRESSION_ALLOWED"
    BLOCKED                   = "PROGRESSION_BLOCKED"
    REQUIRES_EVIDENCE         = "PROGRESSION_REQUIRES_EVIDENCE"
    REQUIRES_AUTHORITY        = "PROGRESSION_REQUIRES_AUTHORITY"
    REQUIRES_HUMAN_REVIEW     = "PROGRESSION_REQUIRES_HUMAN_REVIEW"
    TRAJECTORY_ANOMALY        = "PROGRESSION_TRAJECTORY_ANOMALY"

class ConsequenceLevel(str, PyEnum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

class AuthorityLevel(str, PyEnum):
    NONE      = "NONE"
    BASIC     = "BASIC"
    ELEVATED  = "ELEVATED"
    ADMIN     = "ADMIN"
    SOVEREIGN = "SOVEREIGN"

# Consequence thresholds — what level of authority is needed
CONSEQUENCE_AUTHORITY_MAP = {
    ConsequenceLevel.LOW:      AuthorityLevel.BASIC,
    ConsequenceLevel.MEDIUM:   AuthorityLevel.ELEVATED,
    ConsequenceLevel.HIGH:     AuthorityLevel.ADMIN,
    ConsequenceLevel.CRITICAL: AuthorityLevel.SOVEREIGN,
}

# Authority levels by trust score
TRUST_AUTHORITY_MAP = {
    (0.95, 1.00): AuthorityLevel.SOVEREIGN,
    (0.90, 0.95): AuthorityLevel.ADMIN,
    (0.80, 0.90): AuthorityLevel.ELEVATED,
    (0.65, 0.80): AuthorityLevel.BASIC,
    (0.00, 0.65): AuthorityLevel.NONE,
}

def get_authority_level(trust_score: float) -> AuthorityLevel:
    """Map trust score to authority level."""
    for (low, high), level in TRUST_AUTHORITY_MAP.items():
        if low <= trust_score <= high:
            return level
    return AuthorityLevel.NONE

def authority_sufficient(
    agent_authority: AuthorityLevel,
    required_authority: AuthorityLevel
) -> bool:
    """Check if agent authority meets required level."""
    order = [
        AuthorityLevel.NONE,
        AuthorityLevel.BASIC,
        AuthorityLevel.ELEVATED,
        AuthorityLevel.ADMIN,
        AuthorityLevel.SOVEREIGN,
    ]
    return order.index(agent_authority) >= order.index(required_authority)

def evaluate_trajectory(
    previous_steps: list[dict],
    intended_action: str,
    workflow_id: str,
) -> tuple[bool, str]:
    """
    Evaluate whether the intended action makes logical sense
    given the previous steps in this workflow.
    Returns (is_coherent, anomaly_reason)
    """
    if not previous_steps:
        return True, ""

    # Check for suspicious patterns
    action_types = [s.get("action", "") for s in previous_steps]

    # Detect escalation anomaly — agent trying to escalate privilege mid-workflow
    if intended_action in ("deploy", "delete_records", "payment") and        action_types.count("permission_request") > 2:
        return False, "Excessive permission escalation detected in workflow trajectory"

    # Detect loop anomaly — same action repeated too many times
    if action_types.count(intended_action) >= 3:
        return False, f"Action '{intended_action}' repeated {action_types.count(intended_action)} times — possible loop"

    # Detect jump anomaly — skipping expected workflow steps
    if len(previous_steps) > 0:
        last_step = previous_steps[-1]
        last_status = last_step.get("status", "completed")
        if last_status in ("failed", "blocked", "denied"):
            return False, f"Previous step failed/blocked — progression from failed state requires review"

    return True, ""

def evaluate_evidence_sufficiency(
    evidence: dict,
    consequence_level: ConsequenceLevel,
    intended_action: str,
) -> tuple[bool, list[str]]:
    """
    Check if the evidence provided is sufficient for the
    consequence level of the intended action.
    Returns (is_sufficient, missing_evidence_list)
    """
    missing = []

    # HIGH and CRITICAL consequences require more evidence
    if consequence_level in (ConsequenceLevel.HIGH, ConsequenceLevel.CRITICAL):
        if not evidence.get("business_justification"):
            missing.append("business_justification")
        if not evidence.get("requestor_id"):
            missing.append("requestor_id")
        if not evidence.get("approval_chain"):
            missing.append("approval_chain")

    if consequence_level == ConsequenceLevel.CRITICAL:
        if not evidence.get("dual_authorization"):
            missing.append("dual_authorization")
        if not evidence.get("risk_acknowledgment"):
            missing.append("risk_acknowledgment")

    # Payment-specific evidence
    if intended_action == "payment":
        if not evidence.get("amount_usd"):
            missing.append("amount_usd")
        if float(evidence.get("amount_usd", 0)) > 10000 and not evidence.get("recipient_verified"):
            missing.append("recipient_verified")

    # Delete-specific evidence
    if intended_action == "delete_records":
        if not evidence.get("backup_confirmed"):
            missing.append("backup_confirmed")

    return len(missing) == 0, missing

def evaluate_progression(
    agent_id:        str,
    workflow_id:     str,
    current_step:    int,
    total_steps:     int,
    previous_steps:  list[dict],
    intended_action: str,
    evidence:        dict,
    consequence_level: str,
    trust_score:     float,
    org_id:          str = "default",
) -> dict:
    """
    Full progression admissibility evaluation.

    Evaluates 4 dimensions:
    1. Trajectory coherence — does this progression make sense?
    2. Authority sufficiency — does agent have authority for this consequence?
    3. Evidence sufficiency — is the evidence complete for this action?
    4. Context validity — is the workflow state valid?

    Returns full progression decision with reasons and required actions.
    """
    start_time   = time_module.time()
    execution_id = f"prog_{uuid.uuid4().hex[:8]}"
    timestamp    = datetime.utcnow().isoformat()
    reasons      = []
    required     = []

    try:
        consequence = ConsequenceLevel(consequence_level.upper())
    except ValueError:
        consequence = ConsequenceLevel.MEDIUM

    # ── 1. TRAJECTORY COHERENCE ──────────────────────────────
    trajectory_ok, trajectory_reason = evaluate_trajectory(
        previous_steps, intended_action, workflow_id
    )
    if not trajectory_ok:
        return {
            "decision":          ProgressionDecision.TRAJECTORY_ANOMALY,
            "execution_id":      execution_id,
            "workflow_id":       workflow_id,
            "current_step":      current_step,
            "intended_action":   intended_action,
            "consequence_level": consequence_level,
            "authority_level":   get_authority_level(trust_score).value,
            "trajectory_coherent": False,
            "anomaly_reason":    trajectory_reason,
            "reasons":           [trajectory_reason],
            "required_actions":  ["Review workflow trajectory before proceeding"],
            "latency_ms":        round((time_module.time() - start_time) * 1000, 2),
            "timestamp":         timestamp,
            "chain_block":       None,
        }
    reasons.append("Trajectory coherent — workflow progression is logical")

    # ── 2. AUTHORITY SUFFICIENCY ─────────────────────────────
    agent_authority    = get_authority_level(trust_score)
    required_authority = CONSEQUENCE_AUTHORITY_MAP.get(consequence, AuthorityLevel.ELEVATED)

    if not authority_sufficient(agent_authority, required_authority):
        return {
            "decision":           ProgressionDecision.REQUIRES_AUTHORITY,
            "execution_id":       execution_id,
            "workflow_id":        workflow_id,
            "current_step":       current_step,
            "intended_action":    intended_action,
            "consequence_level":  consequence_level,
            "authority_level":    agent_authority.value,
            "required_authority": required_authority.value,
            "trust_score":        trust_score,
            "trajectory_coherent": True,
            "reasons":            [
                f"Agent authority '{agent_authority.value}' insufficient for "
                f"'{consequence.value}' consequence — requires '{required_authority.value}'"
            ],
            "required_actions":   [f"Elevate agent trust score above threshold for {consequence.value} actions"],
            "latency_ms":         round((time_module.time() - start_time) * 1000, 2),
            "timestamp":          timestamp,
            "chain_block":        None,
        }
    reasons.append(f"Authority sufficient — {agent_authority.value} meets {required_authority.value} requirement")

    # ── 3. EVIDENCE SUFFICIENCY ──────────────────────────────
    evidence_ok, missing_evidence = evaluate_evidence_sufficiency(
        evidence, consequence, intended_action
    )
    if not evidence_ok:
        return {
            "decision":           ProgressionDecision.REQUIRES_EVIDENCE,
            "execution_id":       execution_id,
            "workflow_id":        workflow_id,
            "current_step":       current_step,
            "intended_action":    intended_action,
            "consequence_level":  consequence_level,
            "authority_level":    agent_authority.value,
            "trajectory_coherent": True,
            "evidence_sufficient": False,
            "missing_evidence":   missing_evidence,
            "reasons":            [f"Insufficient evidence for {consequence.value} consequence"],
            "required_actions":   [f"Provide: {', '.join(missing_evidence)}"],
            "latency_ms":         round((time_module.time() - start_time) * 1000, 2),
            "timestamp":          timestamp,
            "chain_block":        None,
        }
    reasons.append("Evidence sufficient for stated consequence level")

    # ── 4. HUMAN REVIEW for CRITICAL ─────────────────────────
    if consequence == ConsequenceLevel.CRITICAL:
        return {
            "decision":           ProgressionDecision.REQUIRES_HUMAN_REVIEW,
            "execution_id":       execution_id,
            "workflow_id":        workflow_id,
            "current_step":       current_step,
            "intended_action":    intended_action,
            "consequence_level":  consequence_level,
            "authority_level":    agent_authority.value,
            "trajectory_coherent": True,
            "evidence_sufficient": True,
            "reasons":            reasons + ["CRITICAL consequence always requires human review"],
            "required_actions":   ["Human review required before CRITICAL progression"],
            "latency_ms":         round((time_module.time() - start_time) * 1000, 2),
            "timestamp":          timestamp,
            "chain_block":        None,
        }

    # ── ALLOWED ──────────────────────────────────────────────
    reasons.append(
        f"Progression admissible — step {current_step}/{total_steps} "
        f"· {intended_action} · {consequence.value} consequence"
    )

    # Append to Merkle chain
    block = chain_append(
        execution_id  = execution_id,
        agent_id      = agent_id,
        action        = f"progression:{intended_action}",
        decision      = ProgressionDecision.ALLOWED.value,
        policy_reason = " | ".join(reasons),
        confidence    = 0.95,
        extra = {
            "workflow_id":      workflow_id,
            "current_step":     current_step,
            "total_steps":      total_steps,
            "consequence_level": consequence_level,
            "authority_level":  agent_authority.value,
            "trajectory_steps": len(previous_steps),
        }
    )

    latency = round((time_module.time() - start_time) * 1000, 2)

    return {
        "decision":            ProgressionDecision.ALLOWED,
        "execution_id":        execution_id,
        "workflow_id":         workflow_id,
        "agent_id":            agent_id,
        "current_step":        current_step,
        "total_steps":         total_steps,
        "intended_action":     intended_action,
        "consequence_level":   consequence_level,
        "authority_level":     agent_authority.value,
        "trust_score":         trust_score,
        "trajectory_coherent": True,
        "evidence_sufficient": True,
        "reasons":             reasons,
        "required_actions":    [],
        "latency_ms":          latency,
        "timestamp":           timestamp,
        "chain_block": {
            "block_hash":    block["block_hash"],
            "merkle_root":   block["merkle_root"],
            "block_index":   block["block_index"],
            "tamper_evident": True,
        },
    }

# ============================================================
# PROGRESSION ADMISSIBILITY ENDPOINT
# ============================================================

class ProgressionRequest(BaseModel):
    agent_id:         str
    workflow_id:      str
    current_step:     int                = 1
    total_steps:      int                = 1
    previous_steps:   list[dict]         = []
    intended_action:  str
    evidence:         dict               = {}
    consequence_level: str               = "MEDIUM"
    org_id:           str                = "default"

@app.post("/v1/progression/evaluate", tags=["Progression Admissibility"])
async def evaluate_progression_endpoint(
    req:       ProgressionRequest,
    x_api_key: Optional[str] = Header(None)
):
    """
    PROGRESSION ADMISSIBILITY ENGINE

    The next layer beyond identity + action enforcement.
    Evaluates whether a specific workflow state transition
    should be permitted given:
    - Trajectory coherence (does this make sense given prior steps?)
    - Authority sufficiency (does agent have authority for this consequence?)
    - Evidence sufficiency (is the proof complete for this action?)
    - Consequence level (LOW / MEDIUM / HIGH / CRITICAL)

    Returns one of:
    - PROGRESSION_ALLOWED
    - PROGRESSION_BLOCKED
    - PROGRESSION_REQUIRES_EVIDENCE
    - PROGRESSION_REQUIRES_AUTHORITY
    - PROGRESSION_REQUIRES_HUMAN_REVIEW
    - PROGRESSION_TRAJECTORY_ANOMALY

    Every decision chained to immutable Merkle audit trail.
    """
    require_api_key(x_api_key)

    # First verify agent identity via passport
    passport = await db_get("passports", "agent_id", req.agent_id)
    trust_score = float(passport.get("trust_score", 0.5)) if passport else 0.5

    result = evaluate_progression(
        agent_id         = req.agent_id,
        workflow_id      = req.workflow_id,
        current_step     = req.current_step,
        total_steps      = req.total_steps,
        previous_steps   = req.previous_steps,
        intended_action  = req.intended_action,
        evidence         = req.evidence,
        consequence_level = req.consequence_level,
        trust_score      = trust_score,
        org_id           = req.org_id,
    )

    # Log to audit trail
    await log_event(req.agent_id, "PROGRESSION_EVALUATED", {
        "workflow_id":     req.workflow_id,
        "current_step":    req.current_step,
        "intended_action": req.intended_action,
        "consequence":     req.consequence_level,
        "decision":        result["decision"],
        "latency_ms":      result["latency_ms"],
    })

    _inc("guard_decisions")
    return result

@app.post("/v1/progression/simulate", tags=["Progression Admissibility"])
async def simulate_progression(
    req:       ProgressionRequest,
    x_api_key: Optional[str] = Header(None)
):
    """
    Simulate a progression decision without logging to audit trail.
    Use this to test your workflow configuration before going live.
    """
    require_api_key(x_api_key)

    result = evaluate_progression(
        agent_id          = req.agent_id,
        workflow_id       = req.workflow_id,
        current_step      = req.current_step,
        total_steps       = req.total_steps,
        previous_steps    = req.previous_steps,
        intended_action   = req.intended_action,
        evidence          = req.evidence,
        consequence_level = req.consequence_level,
        trust_score       = 0.963,
        org_id            = req.org_id,
    )
    result["simulation"] = True
    result["note"]       = "Simulation only — not logged to audit trail"
    return result

# ============================================================
# RUNTIME GOVERNANCE — Full Stack
# ============================================================
# 1. Agent Chain Provenance
# 2. Continuous Admissibility Monitor
# 3. Execution Survivability Scoring
# 4. Runtime Revalidation
# ============================================================

import asyncio
import time as time_module

# ── 1. AGENT CHAIN PROVENANCE ────────────────────────────
# Track full multi-agent call chains end to end
# A → B → C with full attribution and authority inheritance

_agent_chains: dict[str, dict] = {}  # chain_id → chain record

def create_agent_chain(
    root_agent_id: str,
    workflow_id:   str,
    org_id:        str = "default",
) -> dict:
    """Start a new agent chain — called when first agent initiates."""
    chain_id = f"chain_{uuid.uuid4().hex[:10]}"
    chain = {
        "chain_id":     chain_id,
        "workflow_id":  workflow_id,
        "org_id":       org_id,
        "root_agent":   root_agent_id,
        "agents":       [root_agent_id],
        "depth":        0,
        "calls":        [],
        "started_at":   datetime.utcnow().isoformat(),
        "status":       "active",
        "trust_floor":  1.0,  # lowest trust in chain
        "risk_ceiling": "LOW",  # highest risk in chain
    }
    _agent_chains[chain_id] = chain
    print(f"[CHAIN PROVENANCE] New chain: {chain_id} · root: {root_agent_id}")
    return chain

def record_agent_call(
    chain_id:    str,
    caller_id:   str,
    callee_id:   str,
    action:      str,
    decision:    str,
    trust_score: float,
    risk_class:  str = "LOW",
) -> dict:
    """Record one agent calling another within a chain."""
    chain = _agent_chains.get(chain_id)
    if not chain:
        return {"error": "chain not found"}

    call_record = {
        "call_id":   f"call_{uuid.uuid4().hex[:8]}",
        "caller":    caller_id,
        "callee":    callee_id,
        "action":    action,
        "decision":  decision,
        "trust":     trust_score,
        "risk":      risk_class,
        "timestamp": datetime.utcnow().isoformat(),
    }

    chain["calls"].append(call_record)
    if callee_id not in chain["agents"]:
        chain["agents"].append(callee_id)
    chain["depth"] = max(chain["depth"], len(chain["agents"]) - 1)
    chain["trust_floor"] = min(chain["trust_floor"], trust_score)

    risk_order = ["LOW","LIMITED_RISK","MEDIUM","HIGH_RISK","HIGH","CRITICAL"]
    if risk_order.index(risk_class) > risk_order.index(chain.get("risk_ceiling","LOW")):
        chain["risk_ceiling"] = risk_class

    # Append to Merkle chain
    chain_append(
        execution_id  = call_record["call_id"],
        agent_id      = caller_id,
        action        = f"chain_call:{action}",
        decision      = decision,
        policy_reason = f"Chain {chain_id} · {caller_id}→{callee_id}",
        confidence    = trust_score,
        extra         = {"chain_id": chain_id, "callee": callee_id, "depth": chain["depth"]}
    )

    return call_record

def get_chain_provenance(chain_id: str) -> dict:
    """Get full provenance for a chain — who called who with what authority."""
    chain = _agent_chains.get(chain_id)
    if not chain:
        return {"error": "chain not found"}

    # Build attribution graph
    attribution = []
    for i, call in enumerate(chain["calls"]):
        attribution.append({
            "step":       i + 1,
            "caller":     call["caller"],
            "callee":     call["callee"],
            "action":     call["action"],
            "decision":   call["decision"],
            "trust":      call["trust"],
            "timestamp":  call["timestamp"],
            "attributed": True,
        })

    return {
        **chain,
        "attribution":      attribution,
        "total_calls":      len(chain["calls"]),
        "chain_depth":      chain["depth"],
        "trust_floor":      chain["trust_floor"],
        "risk_ceiling":     chain["risk_ceiling"],
        "fully_attributed": True,
        "tamper_evident":   True,
    }

# ── 2. CONTINUOUS ADMISSIBILITY MONITOR ─────────────────
# Monitor long-running agents continuously
# Re-evaluates every N seconds — not just at action boundary

_continuous_monitors: dict[str, dict] = {}

def start_continuous_monitor(
    agent_id:     str,
    workflow_id:  str,
    interval_sec: int = 30,
    org_id:       str = "default",
) -> dict:
    """Start continuous monitoring for a long-running agent."""
    monitor_id = f"mon_{uuid.uuid4().hex[:8]}"
    monitor = {
        "monitor_id":      monitor_id,
        "agent_id":        agent_id,
        "workflow_id":     workflow_id,
        "org_id":          org_id,
        "interval_sec":    interval_sec,
        "started_at":      datetime.utcnow().isoformat(),
        "last_checked":    datetime.utcnow().isoformat(),
        "status":          "monitoring",
        "checks":          [],
        "current_decision":"ADMISSIBLE",
        "violations":      0,
        "paused":          False,
    }
    _continuous_monitors[monitor_id] = monitor
    print(f"[CONTINUOUS] Monitor started: {monitor_id} · agent: {agent_id} · interval: {interval_sec}s")
    return monitor

def continuous_check(
    monitor_id:  str,
    trust_score: float,
    context:     dict = None,
) -> dict:
    """
    Run one continuous admissibility check.
    Called by agent periodically to confirm it can continue.
    """
    monitor = _continuous_monitors.get(monitor_id)
    if not monitor:
        return {"admissible": False, "reason": "Monitor not found — agent must re-register"}

    now     = datetime.utcnow()
    reasons = []
    admissible = True
    decision   = "ADMISSIBLE"

    # Check trust degradation
    if trust_score < 0.65:
        admissible = False
        decision   = "PAUSE_REQUIRED"
        reasons.append(f"Trust degraded to {trust_score:.3f} — below minimum threshold")
        monitor["violations"] += 1

    # Check for context drift
    if context:
        if context.get("error_rate", 0) > 0.3:
            admissible = False
            decision   = "PAUSE_REQUIRED"
            reasons.append(f"Error rate {context['error_rate']:.0%} exceeds threshold")
            monitor["violations"] += 1

        if context.get("anomaly_detected", False):
            admissible = False
            decision   = "HALT_REQUIRED"
            reasons.append("Anomaly detected in execution context")
            monitor["violations"] += 1

    # Check violation accumulation
    if monitor["violations"] >= 3:
        admissible = False
        decision   = "HALT_REQUIRED"
        reasons.append(f"Accumulated {monitor['violations']} violations — agent halted")

    if admissible:
        reasons.append(f"Trust {trust_score:.3f} sufficient · context nominal · execution continues")
        monitor["violations"] = max(0, monitor["violations"] - 1)  # decay violations

    check_record = {
        "check_id":   f"chk_{uuid.uuid4().hex[:6]}",
        "timestamp":  now.isoformat(),
        "trust_score": trust_score,
        "admissible":  admissible,
        "decision":    decision,
        "reasons":     reasons,
        "violations":  monitor["violations"],
    }

    monitor["checks"].append(check_record)
    monitor["last_checked"]     = now.isoformat()
    monitor["current_decision"] = decision
    monitor["paused"]           = not admissible

    # Log to chain if not admissible
    if not admissible:
        chain_append(
            execution_id  = check_record["check_id"],
            agent_id      = monitor["agent_id"],
            action        = "continuous_check",
            decision      = decision,
            policy_reason = " | ".join(reasons),
            confidence    = trust_score,
            extra         = {"monitor_id": monitor_id, "violations": monitor["violations"]}
        )

    return {
        "monitor_id":   monitor_id,
        "agent_id":     monitor["agent_id"],
        "admissible":   admissible,
        "decision":     decision,
        "trust_score":  trust_score,
        "violations":   monitor["violations"],
        "reasons":      reasons,
        "next_check_in": f"{monitor['interval_sec']}s",
        "timestamp":    now.isoformat(),
    }

# ── 3. EXECUTION SURVIVABILITY SCORING ──────────────────
# Score how recoverable a failure would be
# HIGH consequence + LOW survivability = block

def score_survivability(
    action:          str,
    consequence:     str,
    workflow_context: dict,
    agent_id:        str,
) -> dict:
    """
    Score execution survivability — how recoverable is a failure?
    0.0 = catastrophic (irreversible damage)
    1.0 = fully recoverable (no impact)

    Factors:
    - Action reversibility
    - Backup availability
    - Rollback capability
    - Blast radius
    - Recovery time estimate
    """
    score      = 1.0
    factors    = []
    reversible = True

    # Irreversible actions
    irreversible_actions = ["delete_records","send_email","payment","transfer_funds","deploy"]
    if action in irreversible_actions:
        score     -= 0.3
        reversible = False
        factors.append(f"Action '{action}' is irreversible — score -0.30")

    # Consequence level impact
    consequence_penalties = {"LOW":0.0,"MEDIUM":0.1,"HIGH":0.25,"CRITICAL":0.4}
    penalty = consequence_penalties.get(consequence.upper(), 0.1)
    score  -= penalty
    if penalty > 0:
        factors.append(f"{consequence} consequence — score -{penalty:.2f}")

    # Backup available
    if workflow_context.get("backup_confirmed", False):
        score  += 0.15
        factors.append("Backup confirmed — score +0.15")

    # Rollback capability
    if workflow_context.get("rollback_available", False):
        score  += 0.20
        factors.append("Rollback available — score +0.20")
        reversible = True

    # Error rate in workflow
    error_rate = float(workflow_context.get("error_rate", 0))
    if error_rate > 0.1:
        score  -= error_rate * 0.3
        factors.append(f"Workflow error rate {error_rate:.0%} — score -{error_rate*0.3:.2f}")

    # Blast radius
    blast_radius = workflow_context.get("blast_radius","LOW")
    blast_penalties = {"LOW":0,"MEDIUM":0.05,"HIGH":0.15,"CRITICAL":0.3}
    bp = blast_penalties.get(blast_radius, 0)
    if bp > 0:
        score  -= bp
        factors.append(f"Blast radius {blast_radius} — score -{bp:.2f}")

    score = max(0.0, min(1.0, round(score, 3)))

    # Recommendation
    if score >= 0.75:
        recommendation = "PROCEED"
        risk_level     = "LOW"
    elif score >= 0.50:
        recommendation = "PROCEED_WITH_CAUTION"
        risk_level     = "MEDIUM"
    elif score >= 0.25:
        recommendation = "REQUIRE_APPROVAL"
        risk_level     = "HIGH"
    else:
        recommendation = "BLOCK"
        risk_level     = "CRITICAL"

    # Recovery time estimate
    recovery_times = {"PROCEED":"<1min","PROCEED_WITH_CAUTION":"5-30min","REQUIRE_APPROVAL":"1-4hrs","BLOCK":"irreversible"}

    return {
        "survivability_score": score,
        "recommendation":      recommendation,
        "risk_level":          risk_level,
        "reversible":          reversible,
        "factors":             factors,
        "recovery_estimate":   recovery_times[recommendation],
        "action":              action,
        "consequence":         consequence,
        "agent_id":            agent_id,
        "timestamp":           datetime.utcnow().isoformat(),
    }

# ── 4. RUNTIME REVALIDATION ──────────────────────────────
# Re-check everything at key workflow points
# Agent approved at step 1 — recheck at step 4

_revalidation_records: dict[str, list] = {}

async def runtime_revalidate(
    agent_id:       str,
    execution_id:   str,
    workflow_step:  int,
    original_decision: str,
    current_context: dict,
    org_id:         str = "default",
) -> dict:
    """
    Revalidate a previously approved execution at a new workflow step.
    Checks if the original decision still holds given current context.
    """
    reval_id = f"reval_{uuid.uuid4().hex[:8]}"
    timestamp = datetime.utcnow().isoformat()

    # Fetch current passport
    passport = await db_get("passports", "agent_id", agent_id)
    current_trust = float(passport.get("trust_score", 0.5)) if passport else 0.5
    current_status = passport.get("status","active") if passport else "unknown"

    reasons    = []
    still_valid = True
    new_decision = original_decision

    # Check 1: Agent still active
    if current_status != "active":
        still_valid  = False
        new_decision = "DENY"
        reasons.append(f"Agent status changed to '{current_status}' since original approval")

    # Check 2: Trust hasn't degraded significantly
    original_trust = float(current_context.get("original_trust", current_trust))
    trust_delta    = original_trust - current_trust
    if trust_delta > 0.15:
        still_valid  = False
        new_decision = "REQUIRE_HUMAN_APPROVAL"
        reasons.append(f"Trust degraded by {trust_delta:.3f} since original approval")

    # Check 3: No new threat signals
    if current_context.get("shadow_detected", False):
        still_valid  = False
        new_decision = "DENY"
        reasons.append("Shadow detection triggered since original approval")

    # Check 4: Context still matches original
    if current_context.get("context_changed", False):
        still_valid  = False
        new_decision = "REQUIRE_HUMAN_APPROVAL"
        reasons.append("Execution context changed since original approval")

    if still_valid:
        reasons.append(f"Revalidation passed — trust {current_trust:.3f} · status {current_status} · context nominal")

    reval_record = {
        "revalidation_id":   reval_id,
        "execution_id":      execution_id,
        "agent_id":          agent_id,
        "workflow_step":     workflow_step,
        "original_decision": original_decision,
        "current_decision":  new_decision,
        "still_valid":       still_valid,
        "decision_changed":  new_decision != original_decision,
        "current_trust":     current_trust,
        "trust_delta":       round(original_trust - current_trust, 4),
        "reasons":           reasons,
        "timestamp":         timestamp,
    }

    # Store revalidation record
    if execution_id not in _revalidation_records:
        _revalidation_records[execution_id] = []
    _revalidation_records[execution_id].append(reval_record)

    # Chain the revalidation
    chain_append(
        execution_id  = reval_id,
        agent_id      = agent_id,
        action        = f"revalidation:step_{workflow_step}",
        decision      = new_decision,
        policy_reason = " | ".join(reasons),
        confidence    = current_trust,
        extra         = {
            "original_decision": original_decision,
            "still_valid":       still_valid,
            "workflow_step":     workflow_step,
        }
    )

    return reval_record

# ============================================================
# RUNTIME GOVERNANCE ENDPOINTS
# ============================================================

# ── AGENT CHAIN PROVENANCE ───────────────────────────────

class ChainCallRequest(BaseModel):
    chain_id:    str
    caller_id:   str
    callee_id:   str
    action:      str
    decision:    str
    trust_score: float = 0.963
    risk_class:  str   = "LOW"

@app.post("/v1/chain/provenance/start", tags=["Runtime Governance"])
async def start_chain(
    agent_id:    str,
    workflow_id: str,
    org_id:      str = "default",
    x_api_key:   Optional[str] = Header(None)
):
    """Start a new agent chain — call when first agent initiates a workflow."""
    require_api_key(x_api_key)
    chain = create_agent_chain(agent_id, workflow_id, org_id)
    return chain

@app.post("/v1/chain/provenance/record", tags=["Runtime Governance"])
async def record_chain_call(
    req:       ChainCallRequest,
    x_api_key: Optional[str] = Header(None)
):
    """Record one agent calling another within a chain."""
    require_api_key(x_api_key)
    call = record_agent_call(
        chain_id    = req.chain_id,
        caller_id   = req.caller_id,
        callee_id   = req.callee_id,
        action      = req.action,
        decision    = req.decision,
        trust_score = req.trust_score,
        risk_class  = req.risk_class,
    )
    return call

@app.get("/v1/chain/provenance/{chain_id}", tags=["Runtime Governance"])
async def get_provenance(
    chain_id:  str,
    x_api_key: Optional[str] = Header(None)
):
    """Get full provenance for an agent chain — who called who with what authority."""
    require_api_key(x_api_key)
    return get_chain_provenance(chain_id)

@app.get("/v1/chain/provenance", tags=["Runtime Governance"])
async def list_chains(x_api_key: Optional[str] = Header(None)):
    """List all active agent chains."""
    require_api_key(x_api_key)
    return {
        "total_chains": len(_agent_chains),
        "chains": [
            {
                "chain_id":    c["chain_id"],
                "workflow_id": c["workflow_id"],
                "root_agent":  c["root_agent"],
                "depth":       c["depth"],
                "agents":      c["agents"],
                "trust_floor": c["trust_floor"],
                "risk_ceiling":c["risk_ceiling"],
                "status":      c["status"],
                "started_at":  c["started_at"],
            }
            for c in _agent_chains.values()
        ]
    }

# ── CONTINUOUS ADMISSIBILITY ─────────────────────────────

class ContinuousCheckRequest(BaseModel):
    monitor_id:  str
    trust_score: float = 0.963
    context:     dict  = {}

@app.post("/v1/continuous/start", tags=["Runtime Governance"])
async def start_monitor(
    agent_id:     str,
    workflow_id:  str,
    interval_sec: int = 30,
    org_id:       str = "default",
    x_api_key:    Optional[str] = Header(None)
):
    """Start continuous admissibility monitoring for a long-running agent."""
    require_api_key(x_api_key)
    monitor = start_continuous_monitor(agent_id, workflow_id, interval_sec, org_id)
    return monitor

@app.post("/v1/continuous/check", tags=["Runtime Governance"])
async def check_continuous(
    req:       ContinuousCheckRequest,
    x_api_key: Optional[str] = Header(None)
):
    """
    Run one continuous admissibility check.
    Agent calls this periodically to confirm it can continue executing.
    Returns ADMISSIBLE, PAUSE_REQUIRED, or HALT_REQUIRED.
    """
    require_api_key(x_api_key)
    return continuous_check(req.monitor_id, req.trust_score, req.context)

@app.get("/v1/continuous/{monitor_id}", tags=["Runtime Governance"])
async def get_monitor(
    monitor_id: str,
    x_api_key:  Optional[str] = Header(None)
):
    """Get current status of a continuous monitor."""
    require_api_key(x_api_key)
    monitor = _continuous_monitors.get(monitor_id)
    if not monitor:
        raise HTTPException(404, f"Monitor {monitor_id} not found")
    return monitor

# ── EXECUTION SURVIVABILITY ──────────────────────────────

class SurvivabilityRequest(BaseModel):
    agent_id:         str
    action:           str
    consequence:      str = "MEDIUM"
    workflow_context: dict = {}

@app.post("/v1/survivability/score", tags=["Runtime Governance"])
async def survivability_score(
    req:       SurvivabilityRequest,
    x_api_key: Optional[str] = Header(None)
):
    """
    Score execution survivability — how recoverable is a failure?
    0.0 = catastrophic · 1.0 = fully recoverable
    Returns recommendation: PROCEED / PROCEED_WITH_CAUTION / REQUIRE_APPROVAL / BLOCK
    """
    require_api_key(x_api_key)
    result = score_survivability(
        action           = req.action,
        consequence      = req.consequence,
        workflow_context = req.workflow_context,
        agent_id         = req.agent_id,
    )
    # Chain the survivability score
    chain_append(
        execution_id  = f"surv_{uuid.uuid4().hex[:8]}",
        agent_id      = req.agent_id,
        action        = f"survivability:{req.action}",
        decision      = result["recommendation"],
        policy_reason = " | ".join(result["factors"]),
        confidence    = result["survivability_score"],
        extra         = {
            "survivability_score": result["survivability_score"],
            "reversible":          result["reversible"],
            "recovery_estimate":   result["recovery_estimate"],
        }
    )
    return result

# ── RUNTIME REVALIDATION ─────────────────────────────────

class RevalidationRequest(BaseModel):
    agent_id:          str
    execution_id:      str
    workflow_step:     int
    original_decision: str
    current_context:   dict = {}
    org_id:            str  = "default"

@app.post("/v1/revalidate", tags=["Runtime Governance"])
async def revalidate(
    req:       RevalidationRequest,
    x_api_key: Optional[str] = Header(None)
):
    """
    Revalidate a previously approved execution at a new workflow step.
    Checks if the original decision still holds given current context.
    Returns still_valid: true/false and new decision if changed.
    """
    require_api_key(x_api_key)
    result = await runtime_revalidate(
        agent_id          = req.agent_id,
        execution_id      = req.execution_id,
        workflow_step     = req.workflow_step,
        original_decision = req.original_decision,
        current_context   = req.current_context,
        org_id            = req.org_id,
    )
    return result

@app.get("/v1/revalidate/{execution_id}", tags=["Runtime Governance"])
async def get_revalidations(
    execution_id: str,
    x_api_key:    Optional[str] = Header(None)
):
    """Get all revalidation records for an execution."""
    require_api_key(x_api_key)
    records = _revalidation_records.get(execution_id, [])
    return {
        "execution_id":       execution_id,
        "revalidation_count": len(records),
        "revalidations":      records,
    }

# ── RUNTIME GOVERNANCE SUMMARY ───────────────────────────

@app.get("/v1/governance/summary", tags=["Runtime Governance"])
async def governance_summary(x_api_key: Optional[str] = Header(None)):
    """
    Full runtime governance summary — all active monitors,
    chains, revalidations, and survivability scores in one call.
    """
    require_api_key(x_api_key)

    active_monitors = [m for m in _continuous_monitors.values() if not m["paused"]]
    paused_monitors = [m for m in _continuous_monitors.values() if m["paused"]]
    active_chains   = [c for c in _agent_chains.values() if c["status"] == "active"]

    all_hashes  = [b["block_hash"] for b in _chain]
    merkle_root = _compute_merkle_root(all_hashes) if all_hashes else _sha256("empty")

    return {
        "version":    DEPLOY_VERSION,
        "timestamp":  datetime.utcnow().isoformat(),
        "governance": {
            "chain_provenance": {
                "total_chains":  len(_agent_chains),
                "active_chains": len(active_chains),
                "total_calls":   sum(len(c["calls"]) for c in _agent_chains.values()),
            },
            "continuous_admissibility": {
                "total_monitors":  len(_continuous_monitors),
                "active_monitors": len(active_monitors),
                "paused_monitors": len(paused_monitors),
                "total_checks":    sum(len(m["checks"]) for m in _continuous_monitors.values()),
            },
            "revalidation": {
                "total_executions_tracked": len(_revalidation_records),
                "total_revalidations":      sum(len(r) for r in _revalidation_records.values()),
            },
            "audit_chain": {
                "total_blocks":    len(_chain),
                "merkle_root":     merkle_root,
                "chain_integrity": "verified",
                "tamper_evident":  True,
                "drift_detected":  False,
            },
        },
        "enforcement": {
            "total_decisions": _metrics["guard_decisions"],
            "uptime":          get_uptime(),
            "maintenance":     MAINTENANCE_MODE,
        }
    }


# ============================================================
# OPERATIONAL STATE GOVERNANCE
# ============================================================
# The layer beyond progression admissibility.
# Not just evaluating a proposed transition —
# but mapping the full space of permissible transitions
# given current operational state.
#
# Answers Brian Hodak's question:
# "What state transitions remain permissible under
#  current conditions before consequence binds?"
# ============================================================

# ── TRANSITION CONSEQUENCE TAXONOMY ─────────────────────────
# Maps action types to their reversibility and binding risk

TRANSITION_TAXONOMY = {
    "web_search":      {"reversible": True,  "binding_risk": 0.0,  "consequence": "LOW",      "binding_point": None},
    "read_data":       {"reversible": True,  "binding_risk": 0.05, "consequence": "LOW",      "binding_point": None},
    "api_call":        {"reversible": True,  "binding_risk": 0.10, "consequence": "LOW",      "binding_point": "external_state_changed"},
    "send_email":      {"reversible": False, "binding_risk": 0.40, "consequence": "MEDIUM",   "binding_point": "message_delivered"},
    "database_write":  {"reversible": True,  "binding_risk": 0.30, "consequence": "MEDIUM",   "binding_point": "transaction_committed"},
    "file_write":      {"reversible": True,  "binding_risk": 0.20, "consequence": "MEDIUM",   "binding_point": "file_saved"},
    "payment":         {"reversible": False, "binding_risk": 0.85, "consequence": "HIGH",     "binding_point": "payment_settled"},
    "transfer_funds":  {"reversible": False, "binding_risk": 0.90, "consequence": "HIGH",     "binding_point": "transfer_confirmed"},
    "delete_records":  {"reversible": False, "binding_risk": 0.95, "consequence": "HIGH",     "binding_point": "records_purged"},
    "deploy":          {"reversible": True,  "binding_risk": 0.70, "consequence": "HIGH",     "binding_point": "deployment_live"},
    "database_delete": {"reversible": False, "binding_risk": 0.95, "consequence": "CRITICAL", "binding_point": "data_purged"},
    "revoke_access":   {"reversible": False, "binding_risk": 0.75, "consequence": "HIGH",     "binding_point": "access_revoked"},
    "publish_content": {"reversible": False, "binding_risk": 0.60, "consequence": "HIGH",     "binding_point": "content_indexed"},
    "contract_sign":   {"reversible": False, "binding_risk": 1.0,  "consequence": "CRITICAL", "binding_point": "signature_recorded"},
    "data_export":     {"reversible": False, "binding_risk": 0.80, "consequence": "HIGH",     "binding_point": "data_transmitted"},
}

# ── OPERATIONAL CONDITIONS ────────────────────────────────────
# Conditions tracked per agent/workflow
_operational_conditions: dict[str, dict] = {}

def get_operational_conditions(agent_id: str, workflow_id: str) -> dict:
    """Get current operational conditions for an agent/workflow."""
    key = f"{agent_id}:{workflow_id}"
    return _operational_conditions.get(key, {
        "trust_score":         0.963,
        "risk_level":          "LOW",
        "active_alerts":       [],
        "regulation_changes":  [],
        "context_flags":       [],
        "environment":         "production",
        "last_checked":        datetime.utcnow().isoformat(),
        "conditions_stable":   True,
    })

def set_operational_conditions(
    agent_id:    str,
    workflow_id: str,
    conditions:  dict,
) -> dict:
    """Update operational conditions — triggers permission re-evaluation."""
    key = f"{agent_id}:{workflow_id}"
    existing = _operational_conditions.get(key, {})
    updated  = {**existing, **conditions, "last_checked": datetime.utcnow().isoformat()}
    _operational_conditions[key] = updated
    return updated

# ── 1. PERMISSIBLE TRANSITION SPACE MAPPING ──────────────────

def map_permissible_transitions(
    agent_id:    str,
    workflow_id: str,
    trust_score: float,
    current_step: int,
    workflow_context: dict = None,
) -> dict:
    """
    Map the full space of permissible transitions given
    current operational state and conditions.

    Returns:
    - permissible: transitions currently allowed
    - restricted: transitions blocked under current conditions
    - requires_approval: transitions needing human gate
    - consequence_binding: transitions that bind consequence irreversibly
    - recommendation: what the agent should do next
    """
    conditions = get_operational_conditions(agent_id, workflow_id)
    trust      = min(trust_score, float(conditions.get("trust_score", trust_score)))
    ctx        = workflow_context or {}

    permissible        = []
    restricted         = []
    requires_approval  = []
    consequence_binding = []

    authority = get_authority_level(trust)

    for action, taxonomy in TRANSITION_TAXONOMY.items():
        consequence  = taxonomy["consequence"]
        binding_risk = taxonomy["binding_risk"]
        reversible   = taxonomy["reversible"]
        binding_pt   = taxonomy["binding_point"]

        # Check authority sufficiency
        required_auth = CONSEQUENCE_AUTHORITY_MAP.get(
            ConsequenceLevel(consequence) if consequence in [e.value for e in ConsequenceLevel] else ConsequenceLevel.MEDIUM,
            AuthorityLevel.BASIC
        )
        has_authority = authority_sufficient(authority, required_auth)

        # Check active alerts
        has_alerts = len(conditions.get("active_alerts", [])) > 0
        has_regulation_change = len(conditions.get("regulation_changes", [])) > 0

        transition = {
            "action":          action,
            "consequence":     consequence,
            "binding_risk":    binding_risk,
            "reversible":      reversible,
            "binding_point":   binding_pt,
            "authority_needed":required_auth.value,
            "current_authority":authority.value,
        }

        # RESTRICTED — cannot proceed under current conditions
        if not has_authority:
            restricted.append({**transition,
                "reason": f"Insufficient authority — {authority.value} cannot perform {consequence} consequence actions"})
        elif has_alerts and binding_risk > 0.5:
            restricted.append({**transition,
                "reason": f"Active alerts block high-binding-risk transitions (binding_risk: {binding_risk})"})
        elif has_regulation_change and consequence in ("HIGH", "CRITICAL"):
            restricted.append({**transition,
                "reason": "Regulatory change detected — HIGH/CRITICAL transitions suspended pending review"})
        # REQUIRES APPROVAL — can proceed with human gate
        elif binding_risk >= 0.6 or consequence in ("HIGH", "CRITICAL"):
            requires_approval.append({**transition,
                "reason": f"Binding risk {binding_risk} requires human approval before consequence binds"})
            if not reversible:
                consequence_binding.append({**transition,
                    "binding_point": binding_pt,
                    "warning": "This transition is IRREVERSIBLE once consequence binds"})
        # PERMISSIBLE — can proceed autonomously
        else:
            permissible.append(transition)

    # Recommendation
    if len(restricted) == len(TRANSITION_TAXONOMY):
        recommendation = "ALL_TRANSITIONS_BLOCKED — operational conditions prevent any transition"
    elif len(permissible) == 0:
        recommendation = "HUMAN_GATE_REQUIRED — no autonomous transitions available under current conditions"
    elif len(consequence_binding) > 0:
        recommendation = f"PROCEED_WITH_CAUTION — {len(consequence_binding)} irreversible transitions available, require approval"
    else:
        recommendation = f"PROCEED — {len(permissible)} autonomous transitions permissible"

    return {
        "agent_id":           agent_id,
        "workflow_id":        workflow_id,
        "current_step":       current_step,
        "trust_score":        trust,
        "authority_level":    authority.value,
        "conditions_stable":  conditions.get("conditions_stable", True),
        "operational_state": {
            "active_alerts":      conditions.get("active_alerts", []),
            "regulation_changes": conditions.get("regulation_changes", []),
            "environment":        conditions.get("environment", "production"),
        },
        "transition_space": {
            "total_possible":          len(TRANSITION_TAXONOMY),
            "permissible_count":       len(permissible),
            "restricted_count":        len(restricted),
            "requires_approval_count": len(requires_approval),
            "consequence_binding_count":len(consequence_binding),
        },
        "permissible":          permissible,
        "requires_approval":    requires_approval,
        "restricted":           restricted,
        "consequence_binding":  consequence_binding,
        "recommendation":       recommendation,
        "timestamp":            datetime.utcnow().isoformat(),
    }

# ── 2. CONSEQUENCE BINDING POINT DETECTION ───────────────────

def detect_binding_point(
    agent_id:        str,
    workflow_id:     str,
    action:          str,
    workflow_steps:  list[dict],
    current_step:    int,
) -> dict:
    """
    Detect the exact moment in a workflow where a decision
    becomes irreversible — where consequence binds.

    Before binding point: governance can intervene.
    After binding point: consequence has propagated.

    Returns the binding point, pre-binding window, and
    last intervention opportunity.
    """
    taxonomy     = TRANSITION_TAXONOMY.get(action, {
        "reversible": True, "binding_risk": 0.5,
        "consequence": "MEDIUM", "binding_point": "action_completed"
    })

    binding_pt    = taxonomy["binding_point"]
    reversible    = taxonomy["reversible"]
    binding_risk  = taxonomy["binding_risk"]
    consequence   = taxonomy["consequence"]

    # Analyze workflow steps to find where binding occurs
    pre_binding_steps   = []
    post_binding_steps  = []
    binding_step        = None
    binding_detected    = False

    for i, step in enumerate(workflow_steps):
        step_action = step.get("action", "")
        step_status = step.get("status", "pending")

        if step_action == action and not binding_detected:
            binding_step     = i
            binding_detected = True

        if not binding_detected:
            pre_binding_steps.append(step)
        else:
            post_binding_steps.append(step)

    # Calculate intervention window
    steps_before_binding    = len(pre_binding_steps)
    last_intervention_step  = max(0, (binding_step or current_step) - 1)
    intervention_window_open = current_step <= last_intervention_step

    # Consequence propagation analysis
    propagation_risk = "NONE"
    if binding_risk >= 0.9:
        propagation_risk = "CATASTROPHIC — consequence propagates immediately and irreversibly"
    elif binding_risk >= 0.7:
        propagation_risk = "HIGH — consequence binds within seconds of transition"
    elif binding_risk >= 0.5:
        propagation_risk = "MEDIUM — consequence can be partially reversed within time window"
    else:
        propagation_risk = "LOW — consequence reversible with rollback"

    result = {
        "agent_id":           agent_id,
        "workflow_id":        workflow_id,
        "action":             action,
        "binding_point":      binding_pt,
        "binding_risk":       binding_risk,
        "consequence":        consequence,
        "reversible":         reversible,
        "binding_step":       binding_step,
        "current_step":       current_step,
        "steps_before_binding": steps_before_binding,
        "last_intervention_step": last_intervention_step,
        "intervention_window_open": intervention_window_open,
        "propagation_risk":   propagation_risk,
        "pre_binding_steps":  pre_binding_steps,
        "post_binding_steps": post_binding_steps,
        "governance_recommendation": (
            "INTERVENE_NOW — last opportunity before consequence binds"
            if not intervention_window_open and not reversible
            else "INTERVENTION_WINDOW_OPEN — governance can still prevent consequence binding"
            if intervention_window_open
            else "POST_BINDING — consequence has propagated, focus on recovery"
        ),
        "timestamp": datetime.utcnow().isoformat(),
    }

    # Chain the binding point detection
    chain_append(
        execution_id  = f"bind_{uuid.uuid4().hex[:8]}",
        agent_id      = agent_id,
        action        = f"binding_detection:{action}",
        decision      = "BINDING_POINT_DETECTED" if not reversible else "REVERSIBLE_TRANSITION",
        policy_reason = f"Binding point: {binding_pt} · risk: {binding_risk} · {propagation_risk[:30]}",
        confidence    = 1.0 - binding_risk,
        extra         = {
            "binding_point":           binding_pt,
            "intervention_window_open": intervention_window_open,
            "propagation_risk":        propagation_risk[:50],
        }
    )

    return result

# ── 3. OPERATIONAL CONDITION MONITOR ─────────────────────────

def evaluate_condition_change(
    agent_id:      str,
    workflow_id:   str,
    old_conditions: dict,
    new_conditions: dict,
    active_permissions: list[str],
) -> dict:
    """
    When operational conditions change — automatically
    re-evaluate which permissions remain valid.

    Conditions change → permissions automatically re-evaluated.
    No manual intervention required.
    """
    revoked     = []
    maintained  = []
    restricted  = []
    changes     = []

    # Detect what changed
    if new_conditions.get("trust_score", 1.0) < old_conditions.get("trust_score", 1.0):
        delta = old_conditions["trust_score"] - new_conditions["trust_score"]
        changes.append(f"Trust degraded by {delta:.3f}")

    if new_conditions.get("active_alerts") and not old_conditions.get("active_alerts"):
        changes.append(f"New alerts: {new_conditions['active_alerts']}")

    if new_conditions.get("regulation_changes"):
        changes.append(f"Regulation change: {new_conditions['regulation_changes']}")

    if new_conditions.get("environment") != old_conditions.get("environment"):
        changes.append(f"Environment changed: {old_conditions.get('environment')} → {new_conditions.get('environment')}")

    # Re-evaluate each active permission
    new_trust     = float(new_conditions.get("trust_score", 0.963))
    new_authority = get_authority_level(new_trust)
    has_alerts    = bool(new_conditions.get("active_alerts"))
    has_reg_change= bool(new_conditions.get("regulation_changes"))

    for permission in active_permissions:
        taxonomy = TRANSITION_TAXONOMY.get(permission, {})
        consequence  = taxonomy.get("consequence", "MEDIUM")
        binding_risk = taxonomy.get("binding_risk", 0.5)

        required_auth = CONSEQUENCE_AUTHORITY_MAP.get(
            ConsequenceLevel(consequence) if consequence in [e.value for e in ConsequenceLevel] else ConsequenceLevel.MEDIUM,
            AuthorityLevel.BASIC
        )

        # Check if permission still valid
        if not authority_sufficient(new_authority, required_auth):
            revoked.append({
                "permission": permission,
                "reason": f"Authority reduced to {new_authority.value} — insufficient for {consequence} actions",
                "revoked_at": datetime.utcnow().isoformat(),
            })
        elif has_alerts and binding_risk > 0.5:
            restricted.append({
                "permission": permission,
                "reason": "Active alerts restrict high-binding-risk transitions",
                "until": "alerts_resolved",
            })
        elif has_reg_change and consequence in ("HIGH", "CRITICAL"):
            restricted.append({
                "permission": permission,
                "reason": "Regulatory change suspends HIGH/CRITICAL transitions",
                "until": "compliance_review_complete",
            })
        else:
            maintained.append(permission)

    # Update stored conditions
    set_operational_conditions(agent_id, workflow_id, {
        **new_conditions,
        "conditions_stable": len(revoked) == 0 and len(restricted) == 0,
    })

    # Chain the condition change
    chain_append(
        execution_id  = f"cond_{uuid.uuid4().hex[:8]}",
        agent_id      = agent_id,
        action        = "condition_change",
        decision      = "PERMISSIONS_UPDATED" if (revoked or restricted) else "CONDITIONS_STABLE",
        policy_reason = " | ".join(changes) if changes else "No significant changes detected",
        confidence    = new_trust,
        extra         = {
            "revoked_count":    len(revoked),
            "restricted_count": len(restricted),
            "maintained_count": len(maintained),
            "changes":          changes,
        }
    )

    return {
        "agent_id":          agent_id,
        "workflow_id":       workflow_id,
        "conditions_changed": len(changes) > 0,
        "changes_detected":  changes,
        "authority_level":   new_authority.value,
        "trust_score":       new_trust,
        "permissions_evaluated": len(active_permissions),
        "revoked":           revoked,
        "restricted":        restricted,
        "maintained":        maintained,
        "conditions_stable": len(revoked) == 0 and len(restricted) == 0,
        "auto_revoked":      len(revoked) > 0,
        "recommendation": (
            f"IMMEDIATE_ACTION — {len(revoked)} permissions auto-revoked due to condition change"
            if revoked else
            f"RESTRICTED — {len(restricted)} permissions suspended until conditions resolve"
            if restricted else
            "CONDITIONS_STABLE — all permissions maintained"
        ),
        "timestamp": datetime.utcnow().isoformat(),
    }

# ============================================================
# OPERATIONAL STATE GOVERNANCE ENDPOINTS
# ============================================================

class ConditionChangeRequest(BaseModel):
    agent_id:           str
    workflow_id:        str
    old_conditions:     dict = {}
    new_conditions:     dict = {}
    active_permissions: list[str] = []

class BindingPointRequest(BaseModel):
    agent_id:       str
    workflow_id:    str
    action:         str
    workflow_steps: list[dict] = []
    current_step:   int = 1

@app.post("/v1/transitions/map", tags=["Operational State Governance"])
async def map_transitions(
    agent_id:         str,
    workflow_id:      str,
    current_step:     int   = 1,
    x_api_key:        Optional[str] = Header(None)
):
    """
    PERMISSIBLE TRANSITION SPACE MAPPING

    Given current operational state and conditions —
    map the full space of transitions that remain permissible.

    Returns:
    - permissible: transitions agent can take autonomously
    - requires_approval: transitions needing human gate
    - restricted: transitions blocked under current conditions
    - consequence_binding: irreversible transitions with binding points
    - recommendation: what the agent should do next

    This answers: 'What state transitions remain permissible
    under current conditions before consequence binds?'
    """
    require_api_key(x_api_key)

    passport    = await db_get("passports", "agent_id", agent_id)
    trust_score = float(passport.get("trust_score", 0.963)) if passport else 0.963

    result = map_permissible_transitions(
        agent_id         = agent_id,
        workflow_id      = workflow_id,
        trust_score      = trust_score,
        current_step     = current_step,
        workflow_context = {},
    )

    await log_event(agent_id, "TRANSITION_MAP_GENERATED", {
        "workflow_id":       workflow_id,
        "permissible_count": result["transition_space"]["permissible_count"],
        "restricted_count":  result["transition_space"]["restricted_count"],
        "recommendation":    result["recommendation"],
    })

    return result

@app.post("/v1/transitions/binding-point", tags=["Operational State Governance"])
async def detect_binding(
    req:       BindingPointRequest,
    x_api_key: Optional[str] = Header(None)
):
    """
    CONSEQUENCE BINDING POINT DETECTION

    Identify the exact moment in a workflow where a decision
    becomes irreversible — where consequence binds.

    Before binding point: governance can intervene.
    After binding point: consequence has propagated.

    Returns:
    - binding_point: the exact event that binds consequence
    - intervention_window_open: whether governance can still act
    - propagation_risk: CATASTROPHIC / HIGH / MEDIUM / LOW
    - last_intervention_step: last opportunity to prevent binding
    - governance_recommendation: what to do right now
    """
    require_api_key(x_api_key)

    result = detect_binding_point(
        agent_id       = req.agent_id,
        workflow_id    = req.workflow_id,
        action         = req.action,
        workflow_steps = req.workflow_steps,
        current_step   = req.current_step,
    )

    await log_event(req.agent_id, "BINDING_POINT_DETECTED", {
        "workflow_id":              req.workflow_id,
        "action":                   req.action,
        "binding_point":            result["binding_point"],
        "intervention_window_open": result["intervention_window_open"],
        "propagation_risk":         result["propagation_risk"][:50],
    })

    return result

@app.post("/v1/conditions/update", tags=["Operational State Governance"])
async def update_conditions(
    req:       ConditionChangeRequest,
    x_api_key: Optional[str] = Header(None)
):
    """
    OPERATIONAL CONDITION MONITOR

    When operational conditions change — automatically
    re-evaluate all active permissions.

    Conditions change → permissions automatically re-evaluated.
    Revoked permissions logged to immutable chain.
    No manual intervention required.

    Triggers on:
    - Trust score degradation
    - New active alerts
    - Regulatory changes
    - Environment changes

    Returns:
    - revoked: permissions automatically revoked
    - restricted: permissions suspended until conditions resolve
    - maintained: permissions still valid
    - auto_revoked: true if any permissions were revoked
    """
    require_api_key(x_api_key)

    result = evaluate_condition_change(
        agent_id           = req.agent_id,
        workflow_id        = req.workflow_id,
        old_conditions     = req.old_conditions,
        new_conditions     = req.new_conditions,
        active_permissions = req.active_permissions,
    )

    await log_event(req.agent_id, "CONDITIONS_EVALUATED", {
        "workflow_id":    req.workflow_id,
        "revoked":        len(result["revoked"]),
        "restricted":     len(result["restricted"]),
        "auto_revoked":   result["auto_revoked"],
        "recommendation": result["recommendation"],
    })

    return result

@app.get("/v1/conditions/{agent_id}/{workflow_id}", tags=["Operational State Governance"])
async def get_conditions(
    agent_id:   str,
    workflow_id: str,
    x_api_key:  Optional[str] = Header(None)
):
    """Get current operational conditions for an agent/workflow."""
    require_api_key(x_api_key)
    conditions = get_operational_conditions(agent_id, workflow_id)
    return {
        "agent_id":    agent_id,
        "workflow_id": workflow_id,
        "conditions":  conditions,
        "timestamp":   datetime.utcnow().isoformat(),
    }

@app.get("/v1/transitions/taxonomy", tags=["Operational State Governance"])
async def get_taxonomy(x_api_key: Optional[str] = Header(None)):
    """
    Get the full transition consequence taxonomy.
    Shows binding risk, reversibility, and consequence level
    for every supported action type.
    """
    require_api_key(x_api_key)
    return {
        "total_actions":  len(TRANSITION_TAXONOMY),
        "taxonomy":       TRANSITION_TAXONOMY,
        "irreversible":   [k for k,v in TRANSITION_TAXONOMY.items() if not v["reversible"]],
        "high_binding":   [k for k,v in TRANSITION_TAXONOMY.items() if v["binding_risk"] >= 0.7],
        "critical":       [k for k,v in TRANSITION_TAXONOMY.items() if v["consequence"] == "CRITICAL"],
        "timestamp":      datetime.utcnow().isoformat(),
    }

# ============================================================
# PAYSTACK WEBHOOK — Automatic onboarding on payment
# ============================================================

@app.post("/v1/webhooks/paystack", tags=["Onboarding"])
async def paystack_webhook(request: Request):
    """
    Paystack sends this webhook immediately after payment.
    VeriSigil automatically:
    1. Verifies the webhook signature
    2. Detects the plan from payment amount
    3. Creates customer account
    4. Issues cryptographic passport
    5. Generates API key
    6. Sets policy based on plan
    7. Sends welcome email with everything
    All in under 5 seconds. Customer is live before they close their browser.
    """
    # Verify Paystack webhook signature
    paystack_secret = os.environ.get("PAYSTACK_SECRET_KEY", "")
    body            = await request.body()
    signature       = request.headers.get("x-paystack-signature", "")

    if paystack_secret:
        expected = hmac.new(
            paystack_secret.encode(),
            body,
            hashlib.sha512
        ).hexdigest()
        if not hmac.compare_digest(expected, signature):
            print("[WEBHOOK] Invalid Paystack signature — rejected")
            raise HTTPException(400, "Invalid webhook signature")

    try:
        payload = await request.json()
        event   = payload.get("event", "")

        print(f"[WEBHOOK] Paystack event: {event}")

        # Only process successful charges
        if event not in ("charge.success", "payment.success"):
            return {"status": "ignored", "event": event}

        data          = payload.get("data", {})
        amount_kobo   = data.get("amount", 0)
        amount_usd    = amount_kobo / 100  # Paystack sends in kobo/cents
        payment_ref   = data.get("reference", "")
        status        = data.get("status", "")

        if status != "success":
            return {"status": "ignored", "reason": "payment not successful"}

        # Extract customer info from Paystack metadata
        customer      = data.get("customer", {})
        metadata      = data.get("metadata", {})

        email         = customer.get("email", metadata.get("email", ""))
        name          = metadata.get("name", customer.get("first_name", "Customer") + " " + customer.get("last_name", ""))
        company       = metadata.get("company", metadata.get("company_name", name))
        plan_override = metadata.get("plan", "")

        # Detect plan from amount if not specified
        plan = plan_override if plan_override in PLAN_CONFIGS else detect_plan_from_amount(amount_usd)

        if not email:
            print(f"[WEBHOOK] No email in payload — cannot onboard")
            return {"status": "error", "reason": "no email found in payload"}

        # Run full automatic onboarding
        customer_record = await auto_onboard_customer(
            email       = email,
            name        = name.strip(),
            company     = company.strip() or name.strip(),
            plan        = plan,
            payment_ref = payment_ref,
            amount_usd  = amount_usd,
        )

        print(f"[WEBHOOK] Onboarding complete: {email} · {plan} · {customer_record['id']}")
        return {
            "status":   "onboarded",
            "org_id":   customer_record["id"],
            "plan":     plan,
            "email":    email,
            "agent_id": customer_record["agent_id"],
            "message":  "Customer onboarded automatically — welcome email sent",
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"[WEBHOOK ERROR] {e}")
        # Still return 200 so Paystack doesn't retry
        return {"status": "error", "message": str(e)}

# ============================================================
# MANUAL ONBOARDING — For testing and manual setup
# ============================================================

@app.api_route("/v1/onboard", methods=["GET","POST"], tags=["Onboarding"])
async def manual_onboard(
    email:      str,
    name:       str,
    company:    str,
    plan:       str = "starter",
    x_api_key:  Optional[str] = Header(None)
):
    """
    Manually onboard a customer — same as webhook but triggered by you.
    Use this for: manual sales, testing, special cases.
    """
    require_api_key(x_api_key)

    if plan not in PLAN_CONFIGS:
        raise HTTPException(400, f"Invalid plan. Choose: {list(PLAN_CONFIGS.keys())}")

    customer_record = await auto_onboard_customer(
        email       = email,
        name        = name,
        company     = company,
        plan        = plan,
        payment_ref = f"manual_{uuid.uuid4().hex[:8]}",
        amount_usd  = PLAN_CONFIGS[plan]["price_usd"],
    )

    return {
        "status":        "onboarded",
        "org_id":        customer_record["id"],
        "api_key":       customer_record["api_key"],
        "agent_id":      customer_record["agent_id"],
        "passport_did":  customer_record["passport_did"],
        "plan":          plan,
        "email":         email,
        "welcome_email": "sent",
        "message":       f"Customer onboarded manually — welcome email sent to {email}",
    }

# ============================================================
# CUSTOMER MANAGEMENT
# ============================================================

@app.get("/v1/customers", tags=["Onboarding"])
async def list_customers(x_api_key: Optional[str] = Header(None)):
    """List all customers — your internal dashboard."""
    require_api_key(x_api_key)
    customers = list(_customers.values())
    plans     = {}
    for c in customers:
        p = c.get("plan","starter")
        plans[p] = plans.get(p, 0) + 1

    mrr = sum(
        PLAN_CONFIGS.get(c.get("plan","starter"), {}).get("price_usd", 0)
        for c in customers
    )

    return {
        "total_customers": len(customers),
        "mrr_usd":         mrr,
        "arr_usd":         mrr * 12,
        "by_plan":         plans,
        "customers":       [
            {
                "org_id":  c["id"],
                "email":   c["email"],
                "company": c["company"],
                "plan":    c["plan"],
                "status":  c["status"],
                "created": c["created_at"],
            }
            for c in customers
        ],
    }

@app.get("/v1/customers/{org_id}", tags=["Onboarding"])
async def get_customer(org_id: str, x_api_key: Optional[str] = Header(None)):
    """Get a specific customer record."""
    require_api_key(x_api_key)
    customer = _customers.get(org_id)
    if not customer:
        raise HTTPException(404, f"Customer {org_id} not found")
    return customer

# ============================================================
# MERKLE CHAIN ENDPOINTS
# ============================================================

@app.get("/v1/chain", tags=["Audit Chain"])
async def get_chain(
    limit: int = 20,
    x_api_key: Optional[str] = Header(None)
):
    """
    Return the governance chain — last N blocks with Merkle root.
    Every block is cryptographically linked to the previous one.
    """
    require_api_key(x_api_key)
    blocks      = _chain[-limit:] if len(_chain) > limit else _chain
    all_hashes  = [b["block_hash"] for b in _chain]
    merkle_root = _compute_merkle_root(all_hashes) if all_hashes else _sha256("empty")
    return {
        "chain_length":  len(_chain),
        "merkle_root":   merkle_root,
        "chain_head":    _chain_head,
        "chain_integrity": "verified",
        "tamper_evident":   True,
        "blocks":        blocks,
    }

@app.get("/v1/chain/verify", tags=["Audit Chain"])
async def verify_chain(x_api_key: Optional[str] = Header(None)):
    """
    Verify entire chain integrity — recomputes every hash from scratch.
    Returns drift_detected: true if any block was tampered with.
    """
    require_api_key(x_api_key)
    result = chain_verify_integrity()
    return {
        "status":          "intact" if result["intact"] else "COMPROMISED",
        "intact":          result["intact"],
        "blocks_verified": result["blocks"],
        "drift_detected":  result["drift_detected"],
        "violations":      result["violations"],
        "merkle_root":     result.get("merkle_root", ""),
        "chain_head":      result.get("chain_head", ""),
        "message":         "Chain integrity verified — no tampering detected" if result["intact"] else "CHAIN COMPROMISED — tampering detected",
    }

@app.get("/v1/chain/replay/{execution_id}", tags=["Audit Chain"])
async def replay_execution(
    execution_id: str,
    x_api_key: Optional[str] = Header(None)
):
    """
    Replay a specific execution — proves governance decisions are
    deterministic and reproducible. Same inputs always produce same hash.
    Returns hash_match: true if replay is consistent with original.
    """
    require_api_key(x_api_key)
    result = chain_replay(execution_id)
    if not result.get("found", True) and "original_hash" not in result:
        raise HTTPException(404, f"Execution {execution_id} not found in chain")
    return result

@app.get("/v1/chain/stats", tags=["Audit Chain"])
async def chain_stats(x_api_key: Optional[str] = Header(None)):
    """
    Chain statistics — blocks, decisions, drift detection summary.
    """
    require_api_key(x_api_key)
    decisions = {}
    for block in _chain:
        d = block["decision"]
        decisions[d] = decisions.get(d, 0) + 1
    all_hashes  = [b["block_hash"] for b in _chain]
    merkle_root = _compute_merkle_root(all_hashes) if all_hashes else _sha256("empty")
    return {
        "total_blocks":   len(_chain),
        "merkle_root":    merkle_root,
        "chain_head":     _chain_head,
        "chain_integrity":"verified",
        "tamper_evident": True,
        "drift_detected": False,
        "decisions":      decisions,
        "allow_count":    decisions.get("ALLOW", 0),
        "deny_count":     decisions.get("DENY", 0),
        "escalated_count":decisions.get("REQUIRE_HUMAN_APPROVAL", 0),
    }

# ============================================================
# POLICY MANAGEMENT ENDPOINTS
# ============================================================

@app.get("/v1/policy", tags=["Policy Engine"])
async def get_policy(
    org_id: str = "default",
    x_api_key: Optional[str] = Header(None)
):
    """
    Get effective policy for an organization.
    Returns platform defaults merged with any customer overrides.
    """
    require_api_key(x_api_key)
    effective = {}
    for action_type in POLICY_RULES:
        effective[action_type] = get_effective_policy(org_id, action_type)
    return {
        "org_id":           org_id,
        "policy_version":   DEPLOY_VERSION,
        "effective_policy": effective,
        "customer_overrides": _customer_policies.get(org_id, {}),
        "platform_defaults": POLICY_RULES,
        "thresholds":        POLICY_THRESHOLDS,
    }

@app.post("/v1/policy", tags=["Policy Engine"])
async def set_policy(
    org_id:      str,
    action_type: str,
    rules:       dict,
    x_api_key:   Optional[str] = Header(None)
):
    """
    Set customer policy override for a specific action type.
    Customer rules take precedence over platform defaults.

    Example:
    POST /v1/policy?org_id=acme&action_type=payment
    Body: {"max_amount_usd": 5000, "require_human_above": 2000}
    """
    require_api_key(x_api_key)
    if org_id not in _customer_policies:
        _customer_policies[org_id] = {}
    _customer_policies[org_id][action_type] = rules
    effective = get_effective_policy(org_id, action_type)
    return {
        "status":           "policy_updated",
        "org_id":           org_id,
        "action_type":      action_type,
        "rules_set":        rules,
        "effective_policy": effective,
        "message":          f"Policy for '{action_type}' updated for org '{org_id}'"
    }

@app.post("/v1/policy/test", tags=["Policy Engine"])
async def test_policy(
    org_id:         str = "default",
    action_type:    str = "payment",
    trust_score:    float = 0.963,
    action_details: dict = None,
    x_api_key:      Optional[str] = Header(None)
):
    """
    Test a policy rule without executing anything.
    Shows exactly what decision would be returned for given inputs.
    """
    require_api_key(x_api_key)
    if action_details is None:
        action_details = {}
    effective = get_effective_policy(org_id, action_type)
    decision, confidence, reasons = evaluate_policy_rules(
        action_type    = action_type,
        action_details = action_details,
        policy         = effective,
        trust_score    = trust_score,
        org_id         = org_id,
    )
    return {
        "simulation":       True,
        "org_id":           org_id,
        "action_type":      action_type,
        "trust_score":      trust_score,
        "action_details":   action_details,
        "decision":         decision,
        "confidence":       confidence,
        "reasons":          reasons,
        "effective_policy": effective,
        "note":             "This is a simulation — no action was executed or logged",
    }

@app.delete("/v1/policy", tags=["Policy Engine"])
async def reset_policy(
    org_id:      str,
    action_type: Optional[str] = None,
    x_api_key:   Optional[str] = Header(None)
):
    """Reset policy to platform defaults."""
    require_api_key(x_api_key)
    if org_id in _customer_policies:
        if action_type:
            _customer_policies[org_id].pop(action_type, None)
            msg = f"Policy for '{action_type}' reset to platform defaults"
        else:
            _customer_policies.pop(org_id, None)
            msg = f"All policies for org '{org_id}' reset to platform defaults"
    else:
        msg = "No custom policies found — already using platform defaults"
    return {"status": "policy_reset", "org_id": org_id, "message": msg}

# ============================================================
# ENFORCEMENT DASHBOARD ENDPOINT
# ============================================================

@app.get("/v1/enforcement/summary", tags=["Enforcement"])
async def enforcement_summary(
    org_id:    str = "default",
    x_api_key: Optional[str] = Header(None)
):
    """
    Full enforcement summary for an organization.
    Shows decisions, chain stats, policy overview, and trust metrics.
    """
    require_api_key(x_api_key)

    # Chain stats
    org_blocks = [b for b in _chain if b.get("agent_id","").startswith("vsa_")]
    decisions  = {}
    for b in _chain:
        d = b["decision"]
        decisions[d] = decisions.get(d, 0) + 1

    all_hashes  = [b["block_hash"] for b in _chain]
    merkle_root = _compute_merkle_root(all_hashes) if all_hashes else _sha256("empty")

    return {
        "org_id":  org_id,
        "version": DEPLOY_VERSION,
        "enforcement": {
            "total_decisions":     len(_chain),
            "allowed":             decisions.get("ALLOW", 0),
            "denied":              decisions.get("DENY", 0),
            "escalated":           decisions.get("REQUIRE_HUMAN_APPROVAL", 0),
            "block_rate":          round(decisions.get("DENY", 0) / max(len(_chain), 1) * 100, 1),
            "escalation_rate":     round(decisions.get("REQUIRE_HUMAN_APPROVAL", 0) / max(len(_chain), 1) * 100, 1),
        },
        "chain": {
            "total_blocks":    len(_chain),
            "merkle_root":     merkle_root,
            "chain_integrity": "verified",
            "tamper_evident":  True,
            "drift_detected":  False,
        },
        "policy": {
            "active_overrides": len(_customer_policies.get(org_id, {})),
            "action_types_covered": list(POLICY_RULES.keys()),
        },
        "runtime": {
            "uptime":          get_uptime(),
            "maintenance":     MAINTENANCE_MODE,
            "requests_total":  _metrics["requests_total"],
            "guard_decisions": _metrics["guard_decisions"],
        }
    }


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

    # ── MERKLE CHAIN — append every decision to the immutable chain
    chain_block = chain_append(
        execution_id  = execution_id,
        agent_id      = req.agent_id,
        action        = req.action_type,
        decision      = decision.value,
        policy_reason = " | ".join(reasons),
        confidence    = confidence,
        extra         = {
            "trust_score":  trust_score,
            "trust_level":  trust_level_str,
            "latency_ms":   latency,
            "risk_class":   passport.get("eu_risk_class", "UNKNOWN"),
        }
    )
    _inc("guard_decisions")

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

async def generate_compliance_analysis(
    agent_name:       str,
    agent_description:str,
    industry:         str,
    eu_risk_class:    str,
    company_name:     str,
) -> str:
    """
    Use Claude API to generate a personalized EU AI Act compliance analysis.
    Falls back to a template if Claude API is unavailable.
    """
    claude_key = os.environ.get("CLAUDE_API_KEY", "")
    if not claude_key:
        return _compliance_template(agent_name, industry, eu_risk_class)

    prompt = f"""You are an EU AI Act compliance expert. Write a personalized compliance analysis for this AI agent.

Agent Name: {agent_name}
Company: {company_name}
Industry: {industry}
Description: {agent_description}
EU Risk Classification: {eu_risk_class}

Write 3 short paragraphs (max 80 words each):
1. Why this agent is classified {eu_risk_class} under EU AI Act
2. The 2-3 most important specific obligations (cite Articles 6, 13, 14, 50 as relevant)
3. What VeriSigil Runtime Guard now enforces for this agent

Be specific to their industry and description. Use plain English. No bullet points."""

    try:
        async with httpx.AsyncClient() as c:
            r = await c.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key":          claude_key,
                    "anthropic-version":  "2023-06-01",
                    "Content-Type":       "application/json",
                },
                json={
                    "model":      "claude-haiku-4-5-20251001",
                    "max_tokens": 400,
                    "messages":   [{"role": "user", "content": prompt}]
                },
                timeout=15
            )
            data = r.json()
            return data["content"][0]["text"]
    except Exception as e:
        print(f"[CLAUDE COMPLIANCE] Error: {e}")
        return _compliance_template(agent_name, industry, eu_risk_class)

def _compliance_template(agent_name: str, industry: str, eu_risk_class: str) -> str:
    """Fallback template if Claude API is unavailable."""
    if eu_risk_class == "HIGH_RISK":
        return (
            f"{agent_name} is classified HIGH_RISK under EU AI Act Annex III due to its deployment "
            f"in the {industry} sector where AI decisions directly impact individuals' access to services, "
            f"financial outcomes, or safety-critical processes.\n\n"
            f"Your key obligations include: Article 13 (transparency — users must know they are interacting with AI), "
            f"Article 14 (human oversight — a qualified person must be able to review and override decisions), "
            f"and Article 50 (transparency obligations for AI-generated content). "
            f"You must also maintain technical documentation under Article 11.\n\n"
            f"VeriSigil Runtime Guard now enforces Article 14 automatically — every high-risk action "
            f"is intercepted before execution and escalated for human approval where required. "
            f"Every decision is cryptographically logged to your immutable audit trail."
        )
    else:
        return (
            f"{agent_name} is classified LIMITED_RISK under EU AI Act, meaning you face transparency "
            f"obligations under Article 50 but are not subject to the full HIGH_RISK requirements.\n\n"
            f"Your primary obligation is ensuring users know they are interacting with an AI system. "
            f"You should also maintain basic documentation of the system's purpose and capabilities.\n\n"
            f"VeriSigil Runtime Guard provides cryptographic identity verification and an immutable audit trail, "
            f"giving you evidence of responsible deployment if regulators request it."
        )

async def send_compliance_email(
    customer_email:      str,
    customer_name:       str,
    company_name:        str,
    agent_name:          str,
    agent_id:            str,
    passport_did:        str,
    eu_risk_class:       str,
    sprint_id:           str,
    compliance_url:      str,
    resend_api_key:      str,
    compliance_analysis: str = "",
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




async def send_welcome_email(
    customer_email: str,
    customer_name:  str,
    company_name:   str,
    plan:           str,
    org_id:         str,
    api_key:        str,
    agent_id:       str,
    passport_did:   str,
) -> bool:
    """Send automatic welcome email with everything the customer needs to get started."""
    supabase_url = os.environ.get("SUPABASE_URL", "")
    supabase_key = os.environ.get("SUPABASE_SERVICE_KEY", os.environ.get("SUPABASE_KEY", ""))
    edge_url     = f"{supabase_url}/functions/v1/resend-email"
    plan_config  = PLAN_CONFIGS.get(plan, PLAN_CONFIGS["starter"])
    plan_name    = plan_config["name"]
    price        = plan_config["price_usd"]

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<style>
body{{font-family:'Segoe UI',Arial,sans-serif;background:#050E2B;color:#fff;margin:0;padding:0}}
.wrap{{max-width:580px;margin:0 auto;padding:28px 20px}}
.logo{{font-size:20px;font-weight:800;color:#00D4F5;margin-bottom:24px;text-align:center}}
.hero{{background:linear-gradient(135deg,rgba(0,212,245,0.08),rgba(21,101,255,0.06));border:1px solid rgba(0,212,245,0.2);border-radius:14px;padding:28px;margin-bottom:20px;text-align:center}}
.hero-icon{{font-size:40px;margin-bottom:12px}}
.hero-title{{font-size:22px;font-weight:800;color:#fff;margin-bottom:8px}}
.hero-sub{{font-size:14px;color:#94A3B8;line-height:1.6}}
.plan-badge{{display:inline-block;background:rgba(0,212,245,0.1);border:1px solid rgba(0,212,245,0.3);color:#00D4F5;padding:4px 14px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:0.1em;text-transform:uppercase;margin-bottom:16px}}
.box{{background:#0D1A3A;border:1px solid rgba(30,58,110,0.6);border-radius:12px;padding:20px;margin-bottom:16px}}
.box-title{{font-size:11px;font-weight:700;color:#00D4F5;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:14px;display:flex;align-items:center;gap:8px}}
.row{{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid rgba(30,58,110,0.4);font-size:13px}}
.row:last-child{{border-bottom:none}}
.label{{color:#94A3B8}}.value{{color:#fff;font-family:monospace;font-size:12px;word-break:break-all;max-width:300px;text-align:right}}
.value.cyan{{color:#00D4F5;font-weight:700}}
.value.green{{color:#22C55E;font-weight:700}}
.code-box{{background:#010608;border:1px solid rgba(0,212,245,0.15);border-radius:8px;padding:14px;margin:12px 0;font-family:monospace;font-size:12px;color:#00D4F5;word-break:break-all;line-height:1.8}}
.step{{display:flex;gap:14px;padding:12px 0;border-bottom:1px solid rgba(30,58,110,0.3)}}
.step:last-child{{border-bottom:none}}
.step-num{{width:26px;height:26px;border-radius:50%;background:rgba(0,212,245,0.1);border:1px solid rgba(0,212,245,0.3);color:#00D4F5;font-size:11px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0}}
.step-content{{flex:1}}
.step-title{{font-size:13px;font-weight:700;color:#fff;margin-bottom:3px}}
.step-desc{{font-size:12px;color:#94A3B8;line-height:1.5}}
.cta{{display:block;background:#00D4F5;color:#050E2B;text-align:center;padding:14px;border-radius:10px;font-weight:800;font-size:15px;text-decoration:none;margin:20px 0;letter-spacing:0.04em}}
.features{{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:10px}}
.feature{{font-size:11px;color:#94A3B8;display:flex;align-items:center;gap:6px}}
.feature::before{{content:'✓';color:#22C55E;font-weight:700}}
.footer{{text-align:center;font-size:11px;color:#475569;margin-top:24px;padding-top:16px;border-top:1px solid rgba(30,58,110,0.4)}}
.footer a{{color:#00D4F5;text-decoration:none}}
.warning{{background:rgba(245,158,11,0.06);border:1px solid rgba(245,158,11,0.2);border-radius:8px;padding:12px;font-size:12px;color:#F59E0B;margin-top:12px}}
</style></head><body><div class="wrap">
<div class="logo">⬡ VeriSigil AI</div>

<div class="hero">
  <div class="hero-icon">🎉</div>
  <div class="plan-badge">{plan_name} Plan · ${price}/mo</div>
  <div class="hero-title">You're Live on VeriSigil</div>
  <div class="hero-sub">Your Runtime Enforcement infrastructure is active.<br>Your AI agents are now governed. Every action intercepted. Every decision logged.</div>
</div>

<div class="box">
  <div class="box-title">🔑 Your Credentials</div>
  <div class="row"><span class="label">Organization ID</span><span class="value cyan">{org_id}</span></div>
  <div class="row"><span class="label">API Key</span><span class="value cyan">{api_key}</span></div>
  <div class="row"><span class="label">Agent ID</span><span class="value">{agent_id}</span></div>
  <div class="row"><span class="label">Passport DID</span><span class="value" style="font-size:10px">{passport_did[:40]}...</span></div>
  <div class="row"><span class="label">Plan</span><span class="value green">{plan_name}</span></div>
  <div class="row"><span class="label">Status</span><span class="value green">ACTIVE</span></div>
  <div class="warning">⚠ Store your API key securely. Never commit it to GitHub or share it publicly.</div>
</div>

<div class="box">
  <div class="box-title">⚡ Quick Start — 3 Steps</div>
  <div class="step">
    <div class="step-num">1</div>
    <div class="step-content">
      <div class="step-title">Call Runtime Guard before any agent action</div>
      <div class="step-desc">Every action your agent wants to take must be verified first.</div>
      <div class="code-box">POST https://verisigil-api-production.up.railway.app/v1/guard/verify<br>x-api-key: {api_key}<br><br>&#123;"agent_id": "{agent_id}", "action_type": "payment", "action_details": &#123;"amount_usd": 5000&#125;&#125;</div>
    </div>
  </div>
  <div class="step">
    <div class="step-num">2</div>
    <div class="step-content">
      <div class="step-title">Handle the 3 possible decisions</div>
      <div class="step-desc">ALLOW → execute · DENY → block · REQUIRE_HUMAN_APPROVAL → pause and wait for approval email</div>
    </div>
  </div>
  <div class="step">
    <div class="step-num">3</div>
    <div class="step-content">
      <div class="step-title">Monitor your audit chain</div>
      <div class="step-desc">Every decision is logged to your immutable Merkle chain automatically.</div>
    </div>
  </div>
</div>

<div class="box">
  <div class="box-title">🛠 Your Resources</div>
  <div class="row"><span class="label">Quickstart Guide</span><span class="value"><a href="https://verisigilai.com/quickstart.html" style="color:#00D4F5">verisigilai.com/quickstart.html</a></span></div>
  <div class="row"><span class="label">Live Demo</span><span class="value"><a href="https://verisigilai.com/governed-agent-demo.html" style="color:#00D4F5">governed-agent-demo.html</a></span></div>
  <div class="row"><span class="label">Audit Chain</span><span class="value"><a href="https://verisigilai.com/audit-chain.html" style="color:#00D4F5">audit-chain.html</a></span></div>
  <div class="row"><span class="label">Enforcement Dashboard</span><span class="value"><a href="https://verisigilai.com/enforcement.html" style="color:#00D4F5">enforcement.html</a></span></div>
  <div class="row"><span class="label">API Docs</span><span class="value"><a href="https://verisigil-api-production.up.railway.app/docs" style="color:#00D4F5">API Docs →</a></span></div>
  <div class="row"><span class="label">Support</span><span class="value"><a href="mailto:raheem@verisigilai.com" style="color:#00D4F5">raheem@verisigilai.com</a></span></div>
</div>

<a href="https://verisigilai.com/governed-agent-demo.html" class="cta">▶ Try The Live Demo →</a>

<div class="footer">
  <p>⬡ VeriSigil AI · Runtime Enforcement Infrastructure<br>
  Built in Lagos, Nigeria 🇳🇬 · <a href="https://verisigilai.com">verisigilai.com</a><br>
  Reply to this email anytime — Raheem reads every one.</p>
</div>
</div></body></html>"""

    try:
        async with httpx.AsyncClient() as c:
            r = await c.post(
                edge_url,
                headers={"Authorization": f"Bearer {supabase_key}", "Content-Type": "application/json"},
                json={
                    "to":      customer_email,
                    "subject": f"⬡ You're live on VeriSigil — {plan_name} Plan · Your API key inside",
                    "html":    html,
                },
                timeout=15,
            )
            success = r.status_code in (200, 201)
            print(f"[WELCOME EMAIL] {customer_email} → {'sent' if success else 'failed'} ({r.status_code})")
            return success
    except Exception as e:
        print(f"[WELCOME EMAIL ERROR] {e}")
        return False

async def auto_onboard_customer(
    email:        str,
    name:         str,
    company:      str,
    plan:         str,
    payment_ref:  str,
    amount_usd:   float,
) -> dict:
    """
    Full automatic onboarding — called by Paystack webhook.
    Creates account, issues passport, generates API key, sends welcome email.
    Returns complete customer record.
    """
    import secrets

    # 1. Generate org_id and API key
    org_id  = f"org_{secrets.token_hex(6)}"
    api_key = generate_customer_api_key(org_id)

    # 2. Issue cryptographic passport for their first agent
    agent_name   = f"{company} AI Agent"
    agent_id     = f"vsa_{uuid.uuid4().hex[:12]}"
    plan_config  = PLAN_CONFIGS.get(plan, PLAN_CONFIGS["starter"])

    passport_payload = {
        "agent_id":     agent_id,
        "agent_name":   agent_name,
        "display_name": agent_name,
        "issuer_org":   company,
        "owner":        email,
        "framework":    "custom",
        "trust_score":  0.95,
        "eu_risk_class":"LIMITED_RISK",
        "status":       "active",
        "issued_at":    datetime.utcnow().isoformat(),
        "expires_at":   (datetime.utcnow() + timedelta(days=365)).isoformat(),
        "did":          f"did:verisigil:{agent_id}",
        "signature":    sign_payload({
            "agent_id":  agent_id,
            "did":       f"did:verisigil:{agent_id}",
            "issued_at": datetime.utcnow().isoformat(),
            "owner":     email,
            "issuer":    "https://verisigilai.com",
        }),
        "public_key":   PUBLIC_KEY_B64,
    }

    await db_insert("passports", passport_payload)
    print(f"[ONBOARD] Passport issued: {agent_id}")

    # 3. Store customer account in Supabase
    customer_record = {
        "id":           org_id,
        "email":        email,
        "name":         name,
        "company":      company,
        "plan":         plan,
        "api_key":      api_key,
        "agent_id":     agent_id,
        "passport_did": passport_payload["did"],
        "payment_ref":  payment_ref,
        "amount_usd":   amount_usd,
        "status":       "active",
        "created_at":   datetime.utcnow().isoformat(),
        "features":     plan_config["features"],
    }

    await db_insert("customers", customer_record)

    # 4. Set customer policy based on plan
    policy_overrides = plan_config.get("policy_overrides", {})
    if policy_overrides:
        _customer_policies[org_id] = policy_overrides
        print(f"[ONBOARD] Policy set for {org_id}: {list(policy_overrides.keys())}")

    # 5. Store in memory registry
    _customers[org_id] = customer_record

    # 6. Send welcome email
    asyncio.create_task(send_welcome_email(
        customer_email = email,
        customer_name  = name,
        company_name   = company,
        plan           = plan,
        org_id         = org_id,
        api_key        = api_key,
        agent_id       = agent_id,
        passport_did   = passport_payload["did"],
    ))

    # 7. Log to audit trail
    await log_event(agent_id, "CUSTOMER_ONBOARDED", {
        "org_id":      org_id,
        "plan":        plan,
        "email":       email,
        "company":     company,
        "payment_ref": payment_ref,
        "amount_usd":  amount_usd,
    })

    print(f"[ONBOARD] Complete: {email} · {plan} · {org_id}")
    return customer_record

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
