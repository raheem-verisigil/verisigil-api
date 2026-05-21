"""
VeriSigil Runtime Enforcement Layer (REL) SDK
==============================================
One file. One import. Drop into any Python stack in 15 minutes.

Usage:
    from verisigil import VeriSigil, enforce, PaymentAction

    vs = VeriSigil(api_key="your-key")

    # Decorator — wraps any function
    @vs.enforce(consequence="HIGH", jurisdiction="EU")
    def process_payment(amount, recipient, currency):
        ...

    # Manual gate — explicit check before action
    result = vs.gate(
        agent_id="payment-agent-001",
        action_type="PAYMENT_EXECUTION",
        payload={"amount": 50000, "recipient": "vendor-x"},
        consequence="CRITICAL",
    )
    if result.allowed:
        execute_payment()

    # FastAPI middleware — automatic for all routes
    app.add_middleware(VeriSigilMiddleware, api_key="your-key")

Supports:
    - Direct Python decorator
    - Manual gate check
    - FastAPI middleware
    - LangChain tool wrapper
    - Async and sync
    - Automatic accountability records (VGS-024)
    - Automatic audit chain logging
"""

import os
import uuid
import json
import time
import hashlib
import logging
import functools
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Callable, List
from dataclasses import dataclass, field, asdict

# Optional imports — SDK works without them
try:
    import httpx
    _HAS_HTTPX = True
except ImportError:
    import urllib.request
    import urllib.error
    _HAS_HTTPX = False

try:
    from fastapi import Request, Response
    from starlette.middleware.base import BaseHTTPMiddleware
    _HAS_FASTAPI = True
except ImportError:
    _HAS_FASTAPI = False

logger = logging.getLogger("verisigil")


# ── CONSTANTS ─────────────────────────────────────────────────
DEFAULT_API_URL = "https://verisigil-api-production.up.railway.app"
SDK_VERSION     = "1.0.0"
TIMEOUT_SECONDS = 10


# ── DATA CLASSES ──────────────────────────────────────────────

@dataclass
class GovernanceResult:
    """
    Result of a VeriSigil governance check.
    Always check result.allowed before executing any action.
    """
    allowed:           bool
    decision:          str          # ALLOW / DENY / REQUIRE_HUMAN_APPROVAL / MONITOR
    reason:            str
    agent_id:          str
    action_type:       str
    trust_score:       float        = 0.0
    consequence:       str          = "MEDIUM"
    jurisdiction:      str          = "GLOBAL"
    governance_id:     str          = ""
    accountability_id: str          = ""
    escalation_required: bool       = False
    audit_hash:        str          = ""
    timestamp:         str          = ""
    raw_response:      dict         = field(default_factory=dict)
    latency_ms:        float        = 0.0

    @property
    def denied(self) -> bool:
        return not self.allowed

    @property
    def needs_human(self) -> bool:
        return self.decision == "REQUIRE_HUMAN_APPROVAL"

    def to_dict(self) -> dict:
        return asdict(self)

    def __repr__(self):
        status = "✅ ALLOW" if self.allowed else "🚫 DENY"
        if self.needs_human:
            status = "👤 HUMAN REQUIRED"
        return (
            f"GovernanceResult({status} | "
            f"agent={self.agent_id} | "
            f"action={self.action_type} | "
            f"trust={self.trust_score:.3f} | "
            f"consequence={self.consequence})"
        )


@dataclass
class DocumentVerifyResult:
    """Result of a document integrity verification."""
    corruption_detected:  bool
    corruption_score:     float
    integrity_score:      float
    governance_decision:  str
    overall_severity:     str
    semantic_drift:       dict = field(default_factory=dict)
    clause_mutation:      dict = field(default_factory=dict)
    intent_corruption:    dict = field(default_factory=dict)
    numerical_inconsistency: dict = field(default_factory=dict)
    verify_id:            str  = ""
    timestamp:            str  = ""
    raw_response:         dict = field(default_factory=dict)

    @property
    def clean(self) -> bool:
        return not self.corruption_detected

    def __repr__(self):
        status = "✅ CLEAN" if self.clean else f"🚨 CORRUPTED ({self.overall_severity})"
        return (
            f"DocumentVerifyResult({status} | "
            f"score={self.corruption_score:.3f} | "
            f"integrity={self.integrity_score:.1f}% | "
            f"decision={self.governance_decision})"
        )


@dataclass
class AccountabilityRecord:
    """A sealed VGS-024 accountability record."""
    record_id:         str
    agent_id:          str
    action_type:       str
    record_seal:       str
    accountability_grade: str
    legal_defensibility:  str
    created_at:        str
    raw_response:      dict = field(default_factory=dict)

    def __repr__(self):
        return (
            f"AccountabilityRecord("
            f"id={self.record_id} | "
            f"grade={self.accountability_grade} | "
            f"defensibility={self.legal_defensibility})"
        )


# ── HTTP CLIENT ───────────────────────────────────────────────

class _HTTPClient:
    """Thin HTTP client — uses httpx if available, else urllib."""

    def __init__(self, base_url: str, api_key: str, timeout: float = TIMEOUT_SECONDS):
        self.base_url = base_url.rstrip("/")
        self.headers  = {
            "x-api-key":    api_key,
            "Content-Type": "application/json",
            "User-Agent":   f"verisigil-sdk/{SDK_VERSION}",
        }
        self.timeout = timeout

    def post(self, path: str, payload: dict) -> dict:
        url  = f"{self.base_url}{path}"
        data = json.dumps(payload).encode("utf-8")

        if _HAS_HTTPX:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, content=data, headers=self.headers)
                resp.raise_for_status()
                return resp.json()
        else:
            req = urllib.request.Request(url, data=data, headers=self.headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8")
                raise VeriSigilError(f"HTTP {e.code}: {body}") from e

    def get(self, path: str) -> dict:
        url = f"{self.base_url}{path}"
        if _HAS_HTTPX:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.get(url, headers=self.headers)
                resp.raise_for_status()
                return resp.json()
        else:
            req = urllib.request.Request(url, headers=self.headers, method="GET")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))

    async def apost(self, path: str, payload: dict) -> dict:
        if not _HAS_HTTPX:
            raise VeriSigilError("httpx required for async — pip install httpx")
        url = f"{self.base_url}{path}"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(url, json=payload, headers=self.headers)
            resp.raise_for_status()
            return resp.json()


# ── EXCEPTIONS ────────────────────────────────────────────────

class VeriSigilError(Exception):
    """Base VeriSigil SDK error."""

class GovernanceDeniedError(VeriSigilError):
    """Raised when governance check returns DENY and raise_on_deny=True."""
    def __init__(self, result: GovernanceResult):
        self.result = result
        super().__init__(
            f"VeriSigil DENIED: {result.action_type} by {result.agent_id} — {result.reason}"
        )

class HumanApprovalRequired(VeriSigilError):
    """Raised when action requires human approval."""
    def __init__(self, result: GovernanceResult):
        self.result = result
        super().__init__(
            f"VeriSigil HUMAN APPROVAL REQUIRED: {result.action_type} by {result.agent_id}"
        )


# ── MAIN SDK CLASS ────────────────────────────────────────────

class VeriSigil:
    """
    VeriSigil Runtime Enforcement Layer SDK.

    Drop into any Python stack. One import. 15 minutes.

    Example:
        from verisigil import VeriSigil

        vs = VeriSigil(api_key="verisigil-secret-2026")

        result = vs.gate(
            agent_id="payment-agent-001",
            action_type="PAYMENT_EXECUTION",
            payload={"amount": 50000, "currency": "USD"},
            consequence="CRITICAL",
        )

        if result.allowed:
            execute_payment()
        elif result.needs_human:
            notify_supervisor(result)
        else:
            log_denial(result)
    """

    def __init__(
        self,
        api_key:    str  = None,
        api_url:    str  = DEFAULT_API_URL,
        timeout:    float = TIMEOUT_SECONDS,
        agent_id:   str  = None,
        jurisdiction: str = "GLOBAL",
        consequence:  str = "MEDIUM",
        auto_seal:    bool = True,   # auto-create VGS-024 records
        raise_on_deny:bool = False,  # raise GovernanceDeniedError on DENY
        log_level:    str = "INFO",
    ):
        self.api_key      = api_key or os.environ.get("VERISIGIL_API_KEY", "")
        self.api_url      = api_url or os.environ.get("VERISIGIL_API_URL", DEFAULT_API_URL)
        self.agent_id     = agent_id or os.environ.get("VERISIGIL_AGENT_ID", "")
        self.jurisdiction = jurisdiction
        self.consequence  = consequence
        self.auto_seal    = auto_seal
        self.raise_on_deny= raise_on_deny

        if not self.api_key:
            raise VeriSigilError(
                "VeriSigil API key required. Set api_key= or VERISIGIL_API_KEY env var."
            )

        self._http    = _HTTPClient(self.api_url, self.api_key, timeout)
        self._history: List[GovernanceResult] = []

        logging.basicConfig(level=getattr(logging, log_level.upper(), logging.INFO))
        logger.info(f"VeriSigil SDK v{SDK_VERSION} initialized — {self.api_url}")


    # ── CORE: GOVERNANCE GATE ────────────────────────────────

    def gate(
        self,
        action_type:    str,
        agent_id:       str         = None,
        payload:        dict        = None,
        trust_score:    float       = 0.963,
        consequence:    str         = None,
        jurisdiction:   str         = None,
        supervisor_id:  str         = "",
        raise_on_deny:  bool        = None,
    ) -> GovernanceResult:
        """
        Primary governance gate. Call before executing any agent action.

        Returns GovernanceResult with .allowed bool.
        Always check result.allowed before proceeding.

        Example:
            result = vs.gate(
                agent_id="agent-001",
                action_type="DATABASE_WRITE",
                payload={"table": "users", "operation": "delete"},
                consequence="HIGH",
            )
            if result.allowed:
                db.delete(...)
        """
        agent_id    = agent_id    or self.agent_id
        consequence = consequence or self.consequence
        jurisdiction= jurisdiction or self.jurisdiction
        raise_on_deny = raise_on_deny if raise_on_deny is not None else self.raise_on_deny

        if not agent_id:
            raise VeriSigilError("agent_id required in gate() or VeriSigil(agent_id=...)")

        start = time.monotonic()
        try:
            resp = self._http.post("/v1/execution/control", {
                "agent_id":      agent_id,
                "action_type":   action_type,
                "trust_score":   trust_score,
                "jurisdiction":  jurisdiction,
                "consequence":   consequence,
                "supervisor_id": supervisor_id,
                "payload":       payload or {},
                "action_hash":   _hash_payload(payload or {}),
            })
        except Exception as e:
            logger.error(f"VeriSigil gate error: {e}")
            # Fail-safe: deny on error by default
            return GovernanceResult(
                allowed=False, decision="DENY",
                reason=f"VeriSigil unreachable: {e}",
                agent_id=agent_id, action_type=action_type,
                timestamp=_now(),
            )

        latency_ms = (time.monotonic() - start) * 1000
        result     = _parse_governance_result(resp, agent_id, action_type, latency_ms)
        self._history.append(result)

        # Auto-seal accountability record
        if self.auto_seal and not result.allowed:
            try:
                self._seal_accountability(
                    agent_id=agent_id,
                    action_type=action_type,
                    consequence=consequence,
                    supervisor_id=supervisor_id,
                    governance_decision=result.decision,
                    payload=payload or {},
                )
            except Exception as e:
                logger.warning(f"Auto-seal failed: {e}")

        logger.info(f"VeriSigil gate: {result}")

        if raise_on_deny and result.denied and not result.needs_human:
            raise GovernanceDeniedError(result)
        if raise_on_deny and result.needs_human:
            raise HumanApprovalRequired(result)

        return result


    # ── ASYNC GATE ────────────────────────────────────────────

    async def agate(
        self,
        action_type:  str,
        agent_id:     str   = None,
        payload:      dict  = None,
        trust_score:  float = 0.963,
        consequence:  str   = None,
        jurisdiction: str   = None,
    ) -> GovernanceResult:
        """Async version of gate(). Use in FastAPI, async code."""
        agent_id    = agent_id    or self.agent_id
        consequence = consequence or self.consequence
        jurisdiction= jurisdiction or self.jurisdiction

        start = time.monotonic()
        try:
            resp = await self._http.apost("/v1/execution/control", {
                "agent_id":    agent_id,
                "action_type": action_type,
                "trust_score": trust_score,
                "jurisdiction":jurisdiction,
                "consequence": consequence,
                "payload":     payload or {},
                "action_hash": _hash_payload(payload or {}),
            })
        except Exception as e:
            logger.error(f"VeriSigil agate error: {e}")
            return GovernanceResult(
                allowed=False, decision="DENY",
                reason=f"VeriSigil unreachable: {e}",
                agent_id=agent_id, action_type=action_type,
                timestamp=_now(),
            )

        latency_ms = (time.monotonic() - start) * 1000
        result     = _parse_governance_result(resp, agent_id, action_type, latency_ms)
        self._history.append(result)
        logger.info(f"VeriSigil agate: {result}")
        return result


    # ── DECORATOR ─────────────────────────────────────────────

    def enforce(
        self,
        action_type:  str   = None,
        agent_id:     str   = None,
        consequence:  str   = None,
        jurisdiction: str   = None,
        trust_score:  float = 0.963,
        raise_on_deny:bool  = True,
    ):
        """
        Decorator — wraps any function with VeriSigil governance.

        Example:
            @vs.enforce(consequence="CRITICAL", jurisdiction="EU")
            def execute_payment(amount, recipient):
                # VeriSigil checks before this runs
                stripe.charge(amount, recipient)
        """
        def decorator(func: Callable):
            _action = action_type or func.__name__.upper().replace("_", ".")

            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                result = self.gate(
                    agent_id    = agent_id or self.agent_id,
                    action_type = _action,
                    payload     = {"args": str(args)[:200], "kwargs": str(kwargs)[:200]},
                    trust_score = trust_score,
                    consequence = consequence or self.consequence,
                    jurisdiction= jurisdiction or self.jurisdiction,
                    raise_on_deny=raise_on_deny,
                )
                if result.denied:
                    logger.warning(f"VeriSigil blocked {_action}: {result.reason}")
                    return result
                return func(*args, **kwargs)

            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                result = await self.agate(
                    agent_id    = agent_id or self.agent_id,
                    action_type = _action,
                    payload     = {"args": str(args)[:200], "kwargs": str(kwargs)[:200]},
                    trust_score = trust_score,
                    consequence = consequence or self.consequence,
                    jurisdiction= jurisdiction or self.jurisdiction,
                )
                if result.denied:
                    logger.warning(f"VeriSigil blocked {_action}: {result.reason}")
                    if raise_on_deny:
                        raise GovernanceDeniedError(result)
                    return result
                return await func(*args, **kwargs)

            import asyncio
            if asyncio.iscoroutinefunction(func):
                return async_wrapper
            return wrapper

        return decorator


    # ── DOCUMENT VERIFICATION ────────────────────────────────

    def verify_document(
        self,
        original_text:  str,
        generated_text: str,
        document_type:  str   = "GENERAL",
        agent_id:       str   = None,
        consequence:    str   = None,
    ) -> DocumentVerifyResult:
        """
        Verify document integrity — detect semantic drift,
        clause mutation, intent corruption, numerical inconsistency.

        Example:
            result = vs.verify_document(
                original_text="Payment of $50,000 shall not be released without board approval.",
                generated_text="Payment of $5,000 shall be released with management approval.",
                document_type="CONTRACT",
                consequence="CRITICAL",
            )
            if result.corruption_detected:
                block_document(result)
        """
        try:
            resp = self._http.post("/v1/document/semantic-verify", {
                "original_text":  original_text,
                "generated_text": generated_text,
                "document_type":  document_type,
                "agent_id":       agent_id or self.agent_id,
                "consequence":    consequence or self.consequence,
            })
        except Exception as e:
            raise VeriSigilError(f"Document verify failed: {e}") from e

        return DocumentVerifyResult(
            corruption_detected      = resp.get("corruption_detected", False),
            corruption_score         = resp.get("corruption_score", 0.0),
            integrity_score          = resp.get("integrity_score", 100.0),
            governance_decision      = resp.get("governance_decision", "UNKNOWN"),
            overall_severity         = resp.get("overall_severity", "NONE"),
            semantic_drift           = resp.get("semantic_drift", {}),
            clause_mutation          = resp.get("clause_mutation", {}),
            intent_corruption        = resp.get("intent_corruption", {}),
            numerical_inconsistency  = resp.get("numerical_inconsistency", {}),
            verify_id                = resp.get("verify_id", ""),
            timestamp                = resp.get("timestamp", _now()),
            raw_response             = resp,
        )


    # ── ACCOUNTABILITY RECORD (VGS-024) ───────────────────────

    def seal_record(
        self,
        action_type:       str,
        agent_id:          str  = None,
        consequence_class: str  = "OPERATIONAL",
        consequence_detail:str  = "",
        irreversible:      bool = False,
        affected_parties:  list = None,
        financial_impact:  str  = "",
        supervisor_id:     str  = "",
        organization:      str  = "",
        jurisdiction:      str  = None,
    ) -> AccountabilityRecord:
        """
        Seal a VGS-024 Sovereign Accountability Record.
        Cryptographically immutable. Independently verifiable.

        Example:
            record = vs.seal_record(
                agent_id="payment-agent-001",
                action_type="PAYMENT_EXECUTED",
                consequence_class="FINANCIAL",
                irreversible=True,
                financial_impact="$50,000 USD",
                affected_parties=["vendor-x", "org-treasury"],
            )
        """
        try:
            resp = self._http.post("/v1/accountability/execution-record", {
                "agent_id":          agent_id or self.agent_id,
                "action_type":       action_type,
                "consequence_class": consequence_class,
                "consequence_detail":consequence_detail,
                "irreversible":      irreversible,
                "affected_parties":  affected_parties or [],
                "financial_impact":  financial_impact,
                "supervisor_id":     supervisor_id,
                "organization":      organization,
                "jurisdiction":      jurisdiction or self.jurisdiction,
            })
        except Exception as e:
            raise VeriSigilError(f"Seal record failed: {e}") from e

        inv = resp.get("invariant_check", {})
        return AccountabilityRecord(
            record_id            = resp.get("record_id", ""),
            agent_id             = agent_id or self.agent_id,
            action_type          = action_type,
            record_seal          = resp.get("record_seal", ""),
            accountability_grade = inv.get("accountability_grade", "?"),
            legal_defensibility  = inv.get("legal_defensibility", "UNKNOWN"),
            created_at           = resp.get("created_at", _now()),
            raw_response         = resp,
        )


    # ── REGISTER AGENT ────────────────────────────────────────

    def register_agent(
        self,
        agent_id:          str,
        agent_name:        str,
        agent_role:        str   = "EXECUTOR",
        trust_score:       float = 0.963,
        jurisdiction:      str   = None,
        consequence_class: str   = "MEDIUM",
        capabilities:      list  = None,
        owner_org:         str   = "",
    ) -> dict:
        """
        Register an agent in the VeriSigil inventory.
        Call once when agent is created.
        """
        try:
            return self._http.post("/v1/inventory/register", {
                "agent_id":          agent_id,
                "agent_name":        agent_name,
                "agent_role":        agent_role,
                "trust_score":       trust_score,
                "jurisdiction":      jurisdiction or self.jurisdiction,
                "consequence_class": consequence_class,
                "capabilities":      capabilities or [],
                "owner_org":         owner_org,
            })
        except Exception as e:
            raise VeriSigilError(f"Agent registration failed: {e}") from e


    # ── HISTORY & AUDIT ───────────────────────────────────────

    @property
    def history(self) -> List[GovernanceResult]:
        """All governance decisions made in this session."""
        return self._history.copy()

    @property
    def denial_count(self) -> int:
        return sum(1 for r in self._history if r.denied)

    @property
    def allow_count(self) -> int:
        return sum(1 for r in self._history if r.allowed)

    def session_summary(self) -> dict:
        """Summary of all governance decisions in this session."""
        return {
            "total":    len(self._history),
            "allowed":  self.allow_count,
            "denied":   self.denial_count,
            "decisions":{r.decision for r in self._history},
            "agents":   list({r.agent_id for r in self._history}),
        }


    # ── INTERNAL ──────────────────────────────────────────────

    def _seal_accountability(self, **kwargs):
        """Internal auto-seal after deny decisions."""
        try:
            self._http.post("/v1/accountability/execution-record", {
                "agent_id":          kwargs.get("agent_id"),
                "action_type":       kwargs.get("action_type"),
                "consequence_class": kwargs.get("consequence", "OPERATIONAL").upper(),
                "consequence_detail":f"Governance decision: {kwargs.get('governance_decision')}",
                "irreversible":      False,
                "jurisdiction":      self.jurisdiction,
            })
        except Exception:
            pass  # Non-blocking


# ── FASTAPI MIDDLEWARE ────────────────────────────────────────

if _HAS_FASTAPI:
    class VeriSigilMiddleware(BaseHTTPMiddleware):
        """
        FastAPI middleware — automatic governance for all routes.

        Usage:
            from verisigil import VeriSigilMiddleware
            app.add_middleware(
                VeriSigilMiddleware,
                api_key="verisigil-secret-2026",
                protect_paths=["/payments", "/transfers", "/execute"],
                consequence="HIGH",
            )
        """
        def __init__(
            self,
            app,
            api_key:       str,
            protect_paths: List[str] = None,
            agent_id:      str       = "fastapi-agent",
            consequence:   str       = "MEDIUM",
            jurisdiction:  str       = "GLOBAL",
            trust_score:   float     = 0.963,
            block_on_deny: bool      = True,
        ):
            super().__init__(app)
            self.vs            = VeriSigil(api_key=api_key, agent_id=agent_id,
                                           consequence=consequence, jurisdiction=jurisdiction)
            self.protect_paths = protect_paths or []
            self.trust_score   = trust_score
            self.block_on_deny = block_on_deny

        async def dispatch(self, request: Request, call_next):
            path = request.url.path

            # Only govern protected paths
            if self.protect_paths and not any(path.startswith(p) for p in self.protect_paths):
                return await call_next(request)

            action_type = f"{request.method}.{path.strip('/').replace('/', '.').upper()}"

            result = await self.vs.agate(
                action_type  = action_type,
                payload      = {"path": path, "method": request.method},
                trust_score  = self.trust_score,
            )

            if result.denied and self.block_on_deny:
                return Response(
                    content=json.dumps({
                        "error":    "VeriSigil governance denied",
                        "decision": result.decision,
                        "reason":   result.reason,
                        "agent_id": result.agent_id,
                    }),
                    status_code=403,
                    media_type="application/json",
                )

            response = await call_next(request)
            response.headers["X-VeriSigil-Decision"] = result.decision
            response.headers["X-VeriSigil-Trust"]    = str(result.trust_score)
            return response


# ── LANGCHAIN TOOL ────────────────────────────────────────────

class VeriSigilTool:
    """
    LangChain-compatible tool wrapper.
    Wraps any tool with VeriSigil governance.

    Usage:
        from verisigil import VeriSigilTool
        governed_tool = VeriSigilTool(
            tool=my_payment_tool,
            vs=vs,
            consequence="CRITICAL",
        )
    """
    def __init__(self, tool, vs: VeriSigil, consequence: str = "HIGH",
                 agent_id: str = None):
        self.tool        = tool
        self.vs          = vs
        self.consequence = consequence
        self.agent_id    = agent_id or vs.agent_id
        self.name        = getattr(tool, "name", tool.__class__.__name__)

    def run(self, *args, **kwargs):
        result = self.vs.gate(
            agent_id    = self.agent_id,
            action_type = f"LANGCHAIN.{self.name.upper()}",
            payload     = {"args": str(args)[:200], "kwargs": str(kwargs)[:200]},
            consequence = self.consequence,
        )
        if result.denied:
            return f"VeriSigil blocked: {result.reason}"
        return self.tool.run(*args, **kwargs)

    async def arun(self, *args, **kwargs):
        result = await self.vs.agate(
            agent_id    = self.agent_id,
            action_type = f"LANGCHAIN.{self.name.upper()}",
            payload     = {"args": str(args)[:200], "kwargs": str(kwargs)[:200]},
            consequence = self.consequence,
        )
        if result.denied:
            return f"VeriSigil blocked: {result.reason}"
        return await self.tool.arun(*args, **kwargs)


# ── HELPERS ───────────────────────────────────────────────────

def _hash_payload(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _parse_governance_result(
    resp: dict, agent_id: str, action_type: str, latency_ms: float
) -> GovernanceResult:
    decision = resp.get("decision", resp.get("governance_decision", "DENY"))
    allowed  = decision in ("ALLOW", "MONITOR", "WARN", "FLAG_AND_CONTINUE")
    return GovernanceResult(
        allowed            = allowed,
        decision           = decision,
        reason             = resp.get("reason", resp.get("governance_action", "")),
        agent_id           = agent_id,
        action_type        = action_type,
        trust_score        = float(resp.get("trust_score", 0.0)),
        consequence        = resp.get("consequence_class", "MEDIUM"),
        jurisdiction       = resp.get("jurisdiction", "GLOBAL"),
        governance_id      = resp.get("governance_id", resp.get("verify_id", "")),
        escalation_required= resp.get("escalation_required", False),
        audit_hash         = resp.get("audit_hash", resp.get("record_seal", "")),
        timestamp          = resp.get("timestamp", _now()),
        raw_response       = resp,
        latency_ms         = latency_ms,
    )


# ── QUICK START HELPER ────────────────────────────────────────

def quick_start(api_key: str = None, **kwargs) -> VeriSigil:
    """
    Fastest way to get started.

        from verisigil import quick_start
        vs = quick_start("your-api-key")
        result = vs.gate("PAYMENT_EXECUTION", agent_id="agent-001")
    """
    return VeriSigil(api_key=api_key or os.environ.get("VERISIGIL_API_KEY"), **kwargs)


# ── PACKAGE EXPORTS ───────────────────────────────────────────
__all__ = [
    "VeriSigil",
    "VeriSigilError",
    "GovernanceDeniedError",
    "HumanApprovalRequired",
    "GovernanceResult",
    "DocumentVerifyResult",
    "AccountabilityRecord",
    "VeriSigilTool",
    "quick_start",
    "SDK_VERSION",
]

if _HAS_FASTAPI:
    __all__.append("VeriSigilMiddleware")
