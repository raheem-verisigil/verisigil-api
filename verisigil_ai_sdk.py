"""
VeriSigil AI Python SDK — v0.1.0

Five lines to govern any AI action:

    from verisigil_ai import Governance
    gov = Governance(api_key="vs-sandbox-demo-2026b")
    result = gov.intercept(
        agent_id="my-agent",
        action_type="transfer_funds",
        consequence="HIGH",
        payload={"amount": 50000, "to": "acct-999"}
    )
    print(result.ruling)   # ALLOW | DENY | ESCALATE
    print(result.verified) # True — receipt is Ed25519 sealed

HONEST BOUNDARY (from GET /v1/verified-boundary):
- Ruling is deterministic given inputs — not guaranteed to be "correct"
- Consequence tier is evaluated server-side — callers cannot self-declare
  low tier to bypass governance (CV-003 fix, 2026-08-05)
- Receipt proves the governance decision was made — not that the
  downstream action was prevented
- Multi-party attestation requires a genuinely external second signer —
  currently VeriSigil holds both keys (stated gap)

CHANGELOG:
  v0.1.0 (2026-08-05)
  - Initial release
  - Consequence tier computed server-side — callers cannot self-declare
    ADVISORY on a high-value transfer to bypass multi-party requirement
    (gap found during SDK integration testing, fixed before release)
  - fail_closed=True by default — if VeriSigil is unreachable, raise
    GovernanceUnavailable rather than allowing execution to proceed
  - OPEN GAP: multi-party attestation not yet wired into live actuator
    execute path — the requirement is enforced at issuance but not at
    execution time in the current production deployment
  - OPEN GAP: execution continuity and consequence verification are
    standalone-tested modules, not yet wired into the live actuator
"""

import json
import base64
import hashlib
import time
from dataclasses import dataclass, field
from typing import Optional, Any
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


__version__ = "0.1.0"
__package_name__ = "verisigil-ai"

BASE_URL = "https://verisigil-api-production.up.railway.app"
PUBLIC_KEY = "lJWG0Wabt6uATPu5Upo6UEHWGXQqMyi6LMKQC0xwpY8="


class GovernanceError(Exception):
    """Base exception for VeriSigil SDK errors."""


class GovernanceDenied(GovernanceError):
    """Raised when a governance ruling is DENY and raise_on_deny=True."""
    def __init__(self, result):
        self.result = result
        super().__init__(f"Action DENIED: {result.reasons}")


class GovernanceUnavailable(GovernanceError):
    """
    Raised when VeriSigil is unreachable and fail_closed=True (default).

    FAIL-CLOSED is the default and correct behaviour for a governance
    layer. If the governance gate cannot be reached, the action must not
    proceed — a governance gate that fails open is not a governance gate.

    Set fail_closed=False only in explicitly low-stakes contexts where
    degraded operation is acceptable and documented as a conscious choice.
    """


class GovernanceEscalated(GovernanceError):
    """Raised when ruling is ESCALATE and raise_on_escalate=True."""
    def __init__(self, result):
        self.result = result
        super().__init__(f"Action requires human review: {result.conditions}")


@dataclass
class GovernanceResult:
    """
    The sealed result of a pre-execution governance decision.

    Every result contains:
    - ruling: ALLOW | DENY | ESCALATE | ALLOW_WITH_CONDITIONS
    - allowed: bool — True if execution may proceed
    - intercept_id: unique sealed identifier for this decision
    - governance_signature: Ed25519 signature over the canonical receipt
    - verified: bool — True if the signature is structurally present

    Offline verification (no VeriSigil required):
        from nacl.signing import VerifyKey
        import base64, json
        pub = base64.b64decode(result.public_key)
        sig = base64.b64decode(result.governance_signature.replace('Ed25519:', ''))
        payload = json.dumps({...canonical fields...}, sort_keys=True, separators=(',', ':')).encode()
        VerifyKey(pub).verify(payload, sig)  # raises if invalid
    """
    ruling:               str
    allowed:              bool
    intercept_id:         str
    agent_id:             str
    action_type:          str
    consequence:          str
    governance_signature: Optional[str]
    public_key:           str = PUBLIC_KEY
    reasons:              list = field(default_factory=list)
    conditions:           list = field(default_factory=list)
    elapsed_ms:           Optional[float] = None
    payload_hash:         Optional[str] = None
    timestamp:            Optional[str] = None
    raw:                  dict = field(default_factory=dict)

    @property
    def verified(self) -> bool:
        """True if the governance signature is structurally present."""
        return bool(self.governance_signature)

    @property
    def denied(self) -> bool:
        return self.ruling == "DENY"

    @property
    def escalated(self) -> bool:
        return self.ruling == "ESCALATE"

    def verify_offline(self) -> bool:
        """
        Attempt offline Ed25519 verification using PyNaCl.
        Returns True if verified, False if PyNaCl not installed.
        Raises nacl.exceptions.BadSignatureError if signature is invalid.
        """
        try:
            from nacl.signing import VerifyKey
            pub = base64.b64decode(self.public_key)
            sig_str = self.governance_signature or ""
            sig = base64.b64decode(sig_str.replace("Ed25519:", ""))
            canonical = json.dumps({
                "intercept_id": self.intercept_id,
                "agent_id":     self.agent_id,
                "action_type":  self.action_type,
                "ruling":       self.ruling,
                "timestamp":    self.timestamp,
                "consequence":  self.consequence,
                "payload_hash": self.payload_hash,
            }, sort_keys=True, separators=(",", ":")).encode("utf-8")
            VerifyKey(pub).verify(canonical, sig)
            return True
        except ImportError:
            return False  # PyNaCl not installed — install with: pip install pynacl


class Governance:
    """
    VeriSigil Governance client.

    Usage:
        gov = Governance(api_key="vs-sandbox-demo-2026b")
        result = gov.intercept(
            agent_id="my-agent",
            action_type="transfer_funds",
            consequence="HIGH",
            payload={"amount": 50000, "to": "acct-999"},
        )
        if result.allowed:
            execute_the_action()

    Fail-closed by default:
        If VeriSigil is unreachable, GovernanceUnavailable is raised.
        The action must not proceed. This is the correct behaviour for
        a governance layer.

    Parameters:
        api_key:          Your VeriSigil API key
        base_url:         Override the API base URL (default: production)
        fail_closed:      If True (default), raise GovernanceUnavailable
                          when VeriSigil is unreachable rather than
                          allowing execution to proceed
        timeout:          Request timeout in seconds (default: 10)
        raise_on_deny:    If True, raise GovernanceDenied on DENY ruling
        raise_on_escalate:If True, raise GovernanceEscalated on ESCALATE
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = BASE_URL,
        fail_closed: bool = True,
        timeout: int = 10,
        raise_on_deny: bool = False,
        raise_on_escalate: bool = False,
    ):
        self.api_key         = api_key
        self.base_url        = base_url.rstrip("/")
        self.fail_closed     = fail_closed
        self.timeout         = timeout
        self.raise_on_deny   = raise_on_deny
        self.raise_on_escalate = raise_on_escalate

        if not fail_closed:
            import warnings
            warnings.warn(
                "fail_closed=False: VeriSigil unreachability will not block execution. "
                "Only use this in explicitly low-stakes, documented contexts.",
                UserWarning,
                stacklevel=2,
            )

    def _post(self, path: str, body: dict) -> dict:
        """Make an authenticated POST request."""
        url  = f"{self.base_url}{path}"
        data = json.dumps(body).encode("utf-8")
        req  = Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "x-api-key":    self.api_key,
            },
            method="POST",
        )
        try:
            resp = urlopen(req, timeout=self.timeout)
            return json.loads(resp.read().decode("utf-8"))
        except HTTPError as e:
            body_text = e.read().decode("utf-8", errors="replace")
            raise GovernanceError(
                f"VeriSigil API error {e.code}: {body_text[:200]}"
            ) from e
        except URLError as e:
            if self.fail_closed:
                raise GovernanceUnavailable(
                    f"VeriSigil unreachable ({e.reason}). "
                    "Action blocked — fail_closed=True. "
                    "Do not proceed with execution."
                ) from e
            # fail_closed=False: caller decided unreachability is acceptable
            # Return a synthetic ALLOW — caller accepts the risk
            return {
                "ruling":          "ALLOW",
                "allowed":         True,
                "intercept_id":    f"OFFLINE-{int(time.time())}",
                "agent_id":        "",
                "action_type":     "",
                "consequence":     "",
                "governance_signature": None,
                "_offline_degraded": True,
                "_warning": "VeriSigil was unreachable — this action proceeded without governance. Log this incident.",
            }

    def intercept(
        self,
        agent_id:        str,
        action_type:     str,
        consequence:     str,
        payload:         Optional[dict] = None,
        human_present:   bool = False,
        authority_scope: list = None,
        irreversible:    bool = False,
        external_systems:list = None,
        trust_score:     float = 0.8,
        tools_requested: list = None,
        **kwargs,
    ) -> GovernanceResult:
        """
        Intercept an AI agent action before execution.

        This is the primary governance gate. Call this before any
        consequential AI action. If the ruling is DENY or ESCALATE,
        do not proceed with execution.

        Parameters:
            agent_id:        Unique identifier for the AI agent
            action_type:     The action being attempted (e.g. 'transfer_funds')
            consequence:     Consequence tier: ADVISORY | OPERATIONAL | HIGH | CRITICAL | EMERGENCY
                             NOTE: Server-side tier computation validates this. A caller
                             cannot self-declare ADVISORY on a high-stakes action.
            payload:         The action payload (will be hashed for receipt)
            human_present:   Whether a human is present and available for escalation
            authority_scope: List of authority scopes the agent is acting within
            irreversible:    Whether this action cannot be undone
            external_systems:List of external systems this action touches
            trust_score:     Agent trust score 0.0-1.0 (default 0.8)
            tools_requested: List of tools the agent is requesting

        Returns:
            GovernanceResult with ruling, allowed flag, and sealed receipt

        Raises:
            GovernanceDenied:      If ruling is DENY and raise_on_deny=True
            GovernanceEscalated:   If ruling is ESCALATE and raise_on_escalate=True
            GovernanceUnavailable: If VeriSigil unreachable and fail_closed=True (default)
        """
        body = {
            "agent_id":        agent_id,
            "action_type":     action_type,
            "consequence":     consequence,
            "human_present":   human_present,
            "authority_scope": authority_scope or [],
            "irreversible":    irreversible,
            "external_systems":external_systems or [],
            "trust_score":     trust_score,
            "tools_requested": tools_requested or [],
            **kwargs,
        }
        if payload:
            body["payload"] = payload
            body["payload_hash"] = hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()

        raw = self._post("/v1/intercept", body)

        result = GovernanceResult(
            ruling               = raw.get("ruling", "UNKNOWN"),
            allowed              = raw.get("allowed", False),
            intercept_id         = raw.get("intercept_id", ""),
            agent_id             = raw.get("agent_id", agent_id),
            action_type          = raw.get("action_type", action_type),
            consequence          = raw.get("consequence", consequence),
            governance_signature = raw.get("governance_signature"),
            reasons              = raw.get("reasons", []),
            conditions           = raw.get("conditions", []),
            elapsed_ms           = raw.get("elapsed_ms"),
            payload_hash         = raw.get("payload_hash"),
            timestamp            = raw.get("timestamp"),
            raw                  = raw,
        )

        if result.denied and self.raise_on_deny:
            raise GovernanceDenied(result)
        if result.escalated and self.raise_on_escalate:
            raise GovernanceEscalated(result)

        return result

    def issue_ao(
        self,
        agent_id:    str,
        action_type: str,
        consequence: str,
        intercept_id:str,
        actuator_id: str = "",
        state_hash:  str = "",
    ) -> dict:
        """
        Issue an Authorization Object (AO) after a successful intercept.

        The AO is the structural capability the actuator requires to execute.
        Without a valid, unconsumed AO the actuator cannot proceed.

        Call this after a ruling of ALLOW, using the intercept_id from
        the governance result.
        """
        return self._post("/v1/ao/issue", {
            "agent_id":    agent_id,
            "action_type": action_type,
            "consequence": consequence,
            "intercept_id":intercept_id,
            "actuator_id": actuator_id,
            "state_commitment_hash": state_hash,
        })

    def verify_ao(self, ao_id: str, nonce: str, agent_id: str, action_type: str = "") -> dict:
        """
        Verify and consume an Authorization Object.
        Call this at the actuator immediately before executing.
        Returns VALID_AND_UNCONSUMED (proceed) or a rejection reason (halt).
        """
        return self._post("/v1/ao/verify", {
            "ao_id":       ao_id,
            "nonce":       nonce,
            "agent_id":    agent_id,
            "action_type": action_type,
        })

    def get_reputation(self, agent_id: str) -> dict:
        """
        Get the Governance Reputation Score for an agent.
        Score is computed from verified execution history.
        Formula published at GET /v1/reputation/formula — independently recomputable.
        """
        from urllib.request import Request as Req, urlopen as uopen
        url = f"{self.base_url}/v1/reputation/score/{agent_id}"
        req = Req(url, headers={"x-api-key": self.api_key})
        try:
            resp = uopen(req, timeout=self.timeout)
            return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            raise GovernanceError(f"Reputation lookup failed: {e}") from e

    @property
    def verified_boundary(self) -> dict:
        """
        Fetch the live Verified Boundary Statement — what VeriSigil
        proves, what it does not claim, and what is pending.
        No authentication required.
        """
        from urllib.request import urlopen as uopen
        resp = uopen(f"{self.base_url}/v1/verified-boundary", timeout=self.timeout)
        return json.loads(resp.read().decode("utf-8"))


# ── CONVENIENCE FUNCTIONS ────────────────────────────────────

def quick_check(
    agent_id:    str,
    action_type: str,
    consequence: str,
    api_key:     str,
    **kwargs,
) -> GovernanceResult:
    """
    One-function governance check. No client instantiation needed.

    Example:
        from verisigil import quick_check
        result = quick_check("my-agent", "send_email", "ADVISORY", api_key="vs-sandbox-demo-2026b")
        if not result.allowed:
            return  # blocked by governance
    """
    gov = Governance(api_key=api_key)
    return gov.intercept(agent_id=agent_id, action_type=action_type, consequence=consequence, **kwargs)
