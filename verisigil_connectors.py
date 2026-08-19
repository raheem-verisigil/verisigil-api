"""
VeriSigil AI — Agent Framework Connectors
==========================================
Runtime governance for every major AI agent framework.
One import. 15 minutes. Zero trust required.

Supports:
    - LangChain    (Tools, Agents, Chains)
    - CrewAI       (Agents, Tasks, Crews)
    - AutoGen      (AssistantAgent, UserProxyAgent)
    - LangGraph    (StateGraph nodes)
    - Generic      (any Python function or class)

Usage:
    from verisigil_connectors import (
        VeriSigilLangChainTool,
        VeriSigilCrewAIAgent,
        VeriSigilAutoGenAgent,
        VeriSigilLangGraphNode,
        govern,
    )

All connectors share the same governance layer:
    - Every agent action checked before execution
    - ALLOW / DENY / REQUIRE_HUMAN_APPROVAL decisions
    - Automatic VGS-024 accountability records
    - Cryptographically sealed audit trail
    - Independent verifiability — no VeriSigil trust required
"""

import os
import json
import uuid
import hashlib
import logging
import functools
import time as time_module
from datetime import datetime, timezone
from typing import Optional, Any, Callable, Dict, List, Type

logger = logging.getLogger("verisigil.connectors")

# ── OPTIONAL IMPORTS ──────────────────────────────────────────
try:
    import httpx
    _HAS_HTTPX = True
except ImportError:
    import urllib.request
    import urllib.error
    _HAS_HTTPX = False

try:
    from langchain.tools import BaseTool
    from langchain.callbacks.manager import CallbackManagerForToolRun
    _HAS_LANGCHAIN = True
except ImportError:
    try:
        from langchain_core.tools import BaseTool
        _HAS_LANGCHAIN = True
    except ImportError:
        _HAS_LANGCHAIN = False

try:
    from crewai import Agent as CrewAgent, Task as CrewTask
    _HAS_CREWAI = True
except ImportError:
    _HAS_CREWAI = False

try:
    import autogen
    _HAS_AUTOGEN = True
except ImportError:
    _HAS_AUTOGEN = False

try:
    from langgraph.graph import StateGraph
    _HAS_LANGGRAPH = True
except ImportError:
    _HAS_LANGGRAPH = False


# ── CONSTANTS ─────────────────────────────────────────────────
DEFAULT_API_URL = "https://verisigil-api-production.up.railway.app"
CONNECTOR_VERSION = "1.0.0"


# ── EXCEPTIONS ────────────────────────────────────────────────
class VeriSigilConnectorError(Exception):
    pass

class GovernanceDenied(VeriSigilConnectorError):
    def __init__(self, decision, reason, agent_id, action_type):
        self.decision    = decision
        self.reason      = reason
        self.agent_id    = agent_id
        self.action_type = action_type
        super().__init__(f"VeriSigil DENIED: {action_type} by {agent_id} — {reason}")

class HumanApprovalRequired(VeriSigilConnectorError):
    def __init__(self, agent_id, action_type):
        self.agent_id    = agent_id
        self.action_type = action_type
        super().__init__(f"VeriSigil HUMAN APPROVAL REQUIRED: {action_type} by {agent_id}")


# ── CORE GOVERNANCE CLIENT ─────────────────────────────────────

class _GovernanceClient:
    """
    Thin client to VeriSigil governance API.
    Used by all framework connectors.
    """

    def __init__(
        self,
        api_key:     str,
        api_url:     str  = DEFAULT_API_URL,
        agent_id:    str  = "",
        consequence: str  = "HIGH",
        jurisdiction:str  = "GLOBAL",
        timeout:     float= 10.0,
        auto_seal:   bool = True,
    ):
        self.api_key      = api_key or os.environ.get("VERISIGIL_API_KEY", "")
        self.api_url      = api_url.rstrip("/")
        self.agent_id     = agent_id or os.environ.get("VERISIGIL_AGENT_ID", "")
        self.consequence  = consequence
        self.jurisdiction = jurisdiction
        self.timeout      = timeout
        self.auto_seal    = auto_seal
        self._history: List[dict] = []

        if not self.api_key:
            raise VeriSigilConnectorError(
                "VeriSigil API key required. Set api_key= or VERISIGIL_API_KEY env var."
            )

    def _headers(self):
        return {
            "x-api-key":    self.api_key,
            "Content-Type": "application/json",
            "User-Agent":   f"verisigil-connectors/{CONNECTOR_VERSION}",
        }

    def _post(self, path: str, payload: dict) -> dict:
        url  = f"{self.api_url}{path}"
        data = json.dumps(payload).encode("utf-8")
        try:
            if _HAS_HTTPX:
                with httpx.Client(timeout=self.timeout) as client:
                    resp = client.post(url, content=data, headers=self._headers())
                    resp.raise_for_status()
                    return resp.json()
            else:
                req = urllib.request.Request(
                    url, data=data, headers=self._headers(), method="POST"
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            logger.error(f"VeriSigil API error: {e}")
            return {"decision": "DENY", "reason": f"API unreachable: {e}"}

    async def _apost(self, path: str, payload: dict) -> dict:
        if not _HAS_HTTPX:
            raise VeriSigilConnectorError("httpx required for async. pip install httpx")
        url = f"{self.api_url}{path}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, json=payload, headers=self._headers())
                resp.raise_for_status()
                return resp.json()
        except Exception as e:
            logger.error(f"VeriSigil async API error: {e}")
            return {"decision": "DENY", "reason": f"API unreachable: {e}"}

    def gate(
        self,
        action_type:  str,
        agent_id:     str   = None,
        payload:      dict  = None,
        trust_score:  float = 0.963,
        consequence:  str   = None,
        jurisdiction: str   = None,
    ) -> dict:
        """Run governance check. Returns result dict."""
        agent_id    = agent_id    or self.agent_id
        consequence = consequence or self.consequence
        jurisdiction= jurisdiction or self.jurisdiction

        start = time_module.time()
        resp = self._post("/v1/execution/control", {
            "agent_id":    agent_id,
            "action_type": action_type,
            "trust_score": trust_score,
            "jurisdiction":jurisdiction,
            "consequence": consequence,
            "payload":     payload or {},
            "action_hash": hashlib.sha256(
                json.dumps(payload or {}, sort_keys=True, default=str).encode()
            ).hexdigest(),
        })
        latency_ms = round((time_module.time() - start) * 1000, 2)

        decision = resp.get("decision", resp.get("governance_decision", "DENY"))
        allowed  = decision in ("ALLOW", "MONITOR", "WARN", "FLAG_AND_CONTINUE")

        result = {
            "allowed":     allowed,
            "decision":    decision,
            "reason":      resp.get("reason", resp.get("governance_action", "")),
            "agent_id":    agent_id,
            "action_type": action_type,
            "trust_score": resp.get("trust_score", trust_score),
            "latency_ms":  latency_ms,
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "raw":         resp,
        }

        self._history.append(result)

        if self.auto_seal and not allowed:
            try:
                self._post("/v1/accountability/execution-record", {
                    "agent_id":          agent_id,
                    "action_type":       action_type,
                    "consequence_class": consequence.upper(),
                    "consequence_detail":f"Governance decision: {decision}",
                    "irreversible":      False,
                    "jurisdiction":      jurisdiction,
                })
            except Exception:
                pass

        return result

    async def agate(self, action_type: str, agent_id: str = None,
                    payload: dict = None, trust_score: float = 0.963,
                    consequence: str = None, jurisdiction: str = None) -> dict:
        """Async governance check."""
        agent_id    = agent_id    or self.agent_id
        consequence = consequence or self.consequence
        jurisdiction= jurisdiction or self.jurisdiction

        resp = await self._apost("/v1/execution/control", {
            "agent_id":    agent_id,
            "action_type": action_type,
            "trust_score": trust_score,
            "jurisdiction":jurisdiction,
            "consequence": consequence,
            "payload":     payload or {},
        })

        decision = resp.get("decision", resp.get("governance_decision", "DENY"))
        allowed  = decision in ("ALLOW", "MONITOR", "WARN", "FLAG_AND_CONTINUE")

        return {
            "allowed":     allowed,
            "decision":    decision,
            "reason":      resp.get("reason", resp.get("governance_action", "")),
            "agent_id":    agent_id,
            "action_type": action_type,
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "raw":         resp,
        }

    @property
    def history(self):
        return self._history.copy()

    def session_summary(self) -> dict:
        total   = len(self._history)
        allowed = sum(1 for r in self._history if r["allowed"])
        return {
            "total":    total,
            "allowed":  allowed,
            "denied":   total - allowed,
            "agents":   list({r["agent_id"] for r in self._history}),
        }


# ============================================================
# LANGCHAIN CONNECTOR
# ============================================================

if _HAS_LANGCHAIN:
    from pydantic import BaseModel as PydanticBaseModel, Field as PydanticField

    class VeriSigilLangChainTool(BaseTool):
        """
        LangChain Tool with VeriSigil governance.

        Every tool call is checked before execution.
        Denied calls are blocked and logged automatically.

        Usage:
            from verisigil_connectors import VeriSigilLangChainTool

            class PaymentTool(VeriSigilLangChainTool):
                name = "payment_executor"
                description = "Executes payment transactions"
                vs_api_key = "verisigil-secret-2026"
                vs_agent_id = "payment-agent-001"
                vs_consequence = "CRITICAL"

                def _governed_run(self, query: str) -> str:
                    return stripe.charge(query)
        """
        name:           str = "governed_tool"
        description:    str = "A VeriSigil governed tool"

        # VeriSigil config — set in subclass
        vs_api_key:     str = ""
        vs_agent_id:    str = ""
        vs_consequence: str = "HIGH"
        vs_jurisdiction:str = "GLOBAL"
        vs_trust_score: float = 0.963
        vs_raise_on_deny: bool = True

        class Config:
            arbitrary_types_allowed = True

        def _get_client(self) -> _GovernanceClient:
            return _GovernanceClient(
                api_key     = self.vs_api_key or os.environ.get("VERISIGIL_API_KEY", ""),
                agent_id    = self.vs_agent_id,
                consequence = self.vs_consequence,
                jurisdiction= self.vs_jurisdiction,
            )

        def _run(
            self,
            query: str,
            run_manager: Optional[Any] = None,
        ) -> str:
            client = self._get_client()
            result = client.gate(
                action_type  = f"LANGCHAIN.{self.name.upper()}",
                payload      = {"query": query[:500]},
                trust_score  = self.vs_trust_score,
            )

            if not result["allowed"]:
                msg = f"VeriSigil governance denied: {result['reason']}"
                if self.vs_raise_on_deny:
                    raise GovernanceDenied(
                        result["decision"], result["reason"],
                        self.vs_agent_id, f"LANGCHAIN.{self.name.upper()}"
                    )
                return msg

            return self._governed_run(query)

        async def _arun(self, query: str, run_manager: Optional[Any] = None) -> str:
            client = self._get_client()
            result = await client.agate(
                action_type = f"LANGCHAIN.{self.name.upper()}",
                payload     = {"query": query[:500]},
                trust_score = self.vs_trust_score,
            )

            if not result["allowed"]:
                if self.vs_raise_on_deny:
                    raise GovernanceDenied(
                        result["decision"], result["reason"],
                        self.vs_agent_id, f"LANGCHAIN.{self.name.upper()}"
                    )
                return f"VeriSigil denied: {result['reason']}"

            return self._governed_run(query)

        def _governed_run(self, query: str) -> str:
            """Override this in your subclass to implement the tool logic."""
            raise NotImplementedError("Implement _governed_run in your tool subclass")


    def governed_langchain_tool(
        tool_func:   Callable,
        api_key:     str,
        agent_id:    str  = "langchain-agent",
        consequence: str  = "HIGH",
        action_type: str  = None,
        trust_score: float= 0.963,
    ) -> Callable:
        """
        Decorator to add VeriSigil governance to any LangChain tool function.

        Usage:
            @governed_langchain_tool(
                api_key="verisigil-secret-2026",
                agent_id="agent-001",
                consequence="CRITICAL",
            )
            def execute_payment(amount: str) -> str:
                return stripe.charge(amount)
        """
        client = _GovernanceClient(
            api_key=api_key, agent_id=agent_id, consequence=consequence
        )
        _action = action_type or f"LANGCHAIN.{tool_func.__name__.upper()}"

        @functools.wraps(tool_func)
        def wrapper(*args, **kwargs):
            result = client.gate(
                action_type = _action,
                payload     = {"args": str(args)[:200], "kwargs": str(kwargs)[:200]},
                trust_score = trust_score,
            )
            if not result["allowed"]:
                raise GovernanceDenied(
                    result["decision"], result["reason"], agent_id, _action
                )
            return tool_func(*args, **kwargs)

        return wrapper


# ============================================================
# CREWAI CONNECTOR
# ============================================================

class VeriSigilCrewAIAgent:
    """
    CrewAI Agent wrapper with VeriSigil governance.

    Intercepts every task execution before it runs.
    Denied tasks are blocked with full accountability record.

    Usage:
        from verisigil_connectors import VeriSigilCrewAIAgent

        governed_agent = VeriSigilCrewAIAgent(
            api_key      = "verisigil-secret-2026",
            agent_id     = "crewai-payment-agent",
            consequence  = "CRITICAL",
            jurisdiction = "EU",
        )

        # Wrap your CrewAI agent
        result = governed_agent.execute_task(
            task_description = "Transfer $50,000 to vendor account",
            agent_role       = "Payment Executor",
            tools            = [payment_tool],
        )
    """

    def __init__(
        self,
        api_key:     str,
        agent_id:    str  = "crewai-agent",
        consequence: str  = "HIGH",
        jurisdiction:str  = "GLOBAL",
        trust_score: float= 0.963,
        raise_on_deny:bool= True,
    ):
        self._client = _GovernanceClient(
            api_key=api_key, agent_id=agent_id,
            consequence=consequence, jurisdiction=jurisdiction
        )
        self.trust_score   = trust_score
        self.raise_on_deny = raise_on_deny
        self.agent_id      = agent_id

    def execute_task(
        self,
        task_description: str,
        agent_role:       str  = "EXECUTOR",
        tools:            list = None,
        context:          dict = None,
        crew_agent:       Any  = None,
    ) -> Any:
        """
        Execute a CrewAI task with governance check.
        Governance runs BEFORE the task executes.
        """
        action_type = f"CREWAI.{agent_role.upper().replace(' ', '_')}"

        result = self._client.gate(
            action_type = action_type,
            payload     = {
                "task":    task_description[:500],
                "role":    agent_role,
                "tools":   [str(t) for t in (tools or [])][:5],
                "context": str(context or {})[:200],
            },
            trust_score = self.trust_score,
        )

        if not result["allowed"]:
            logger.warning(f"VeriSigil blocked CrewAI task: {result['reason']}")
            if self.raise_on_deny:
                raise GovernanceDenied(
                    result["decision"], result["reason"],
                    self.agent_id, action_type
                )
            return {
                "status":   "DENIED",
                "decision": result["decision"],
                "reason":   result["reason"],
                "task":     task_description,
            }

        # Execute the actual CrewAI task if agent provided
        if crew_agent and _HAS_CREWAI:
            try:
                task = CrewTask(
                    description=task_description,
                    agent=crew_agent,
                )
                return task.execute()
            except Exception as e:
                logger.error(f"CrewAI task execution error: {e}")
                return {"status": "ERROR", "error": str(e)}

        return {
            "status":   "ALLOWED",
            "decision": result["decision"],
            "task":     task_description,
            "governance_id": result["raw"].get("governance_id", ""),
        }

    def govern_crew(self, crew_func: Callable) -> Callable:
        """
        Decorator to govern an entire CrewAI crew execution.

        Usage:
            @governed_agent.govern_crew
            def run_payment_crew():
                return crew.kickoff()
        """
        @functools.wraps(crew_func)
        def wrapper(*args, **kwargs):
            result = self._client.gate(
                action_type = f"CREWAI.CREW.{crew_func.__name__.upper()}",
                payload     = {"args": str(args)[:200]},
                trust_score = self.trust_score,
            )
            if not result["allowed"]:
                raise GovernanceDenied(
                    result["decision"], result["reason"],
                    self.agent_id, crew_func.__name__
                )
            return crew_func(*args, **kwargs)
        return wrapper

    @property
    def session_summary(self) -> dict:
        return self._client.session_summary()


# ============================================================
# AUTOGEN CONNECTOR
# ============================================================

class VeriSigilAutoGenAgent:
    """
    AutoGen Agent wrapper with VeriSigil governance.

    Intercepts agent messages and function calls before execution.
    Works with AssistantAgent, UserProxyAgent, and GroupChat.

    Usage:
        from verisigil_connectors import VeriSigilAutoGenAgent

        governed = VeriSigilAutoGenAgent(
            api_key      = "verisigil-secret-2026",
            agent_id     = "autogen-finance-agent",
            consequence  = "CRITICAL",
        )

        # Govern a function before AutoGen calls it
        @governed.govern_function(consequence="CRITICAL")
        def execute_trade(ticker: str, amount: float) -> str:
            return trading_api.execute(ticker, amount)

        # Govern a full AutoGen conversation initiation
        governed.check_initiation(
            message="Execute a $50,000 trade on AAPL",
            sender_id="user-proxy-001",
        )
    """

    def __init__(
        self,
        api_key:     str,
        agent_id:    str  = "autogen-agent",
        consequence: str  = "HIGH",
        jurisdiction:str  = "GLOBAL",
        trust_score: float= 0.963,
        raise_on_deny:bool= True,
    ):
        self._client = _GovernanceClient(
            api_key=api_key, agent_id=agent_id,
            consequence=consequence, jurisdiction=jurisdiction
        )
        self.trust_score   = trust_score
        self.raise_on_deny = raise_on_deny
        self.agent_id      = agent_id

    def govern_function(
        self,
        consequence: str  = None,
        action_type: str  = None,
        trust_score: float= None,
    ) -> Callable:
        """
        Decorator for AutoGen function calls.

        Usage:
            @governed.govern_function(consequence="CRITICAL")
            def execute_payment(amount: float, recipient: str) -> str:
                ...
        """
        def decorator(func: Callable):
            _action = action_type or f"AUTOGEN.{func.__name__.upper()}"
            _cons   = consequence or self._client.consequence
            _trust  = trust_score or self.trust_score

            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                result = self._client.gate(
                    action_type = _action,
                    payload     = {
                        "function": func.__name__,
                        "args":     str(args)[:300],
                        "kwargs":   str(kwargs)[:300],
                    },
                    trust_score = _trust,
                    consequence = _cons,
                )
                if not result["allowed"]:
                    if self.raise_on_deny:
                        raise GovernanceDenied(
                            result["decision"], result["reason"],
                            self.agent_id, _action
                        )
                    return f"GOVERNANCE_DENIED: {result['reason']}"
                return func(*args, **kwargs)
            return wrapper
        return decorator

    def check_initiation(
        self,
        message:   str,
        sender_id: str = "user-proxy",
    ) -> dict:
        """
        Check before initiating an AutoGen conversation.
        Call this before agent.initiate_chat().
        """
        return self._client.gate(
            action_type = "AUTOGEN.INITIATE_CHAT",
            payload     = {
                "message":   message[:500],
                "sender_id": sender_id,
            },
            trust_score = self.trust_score,
        )

    def check_message(self, message: str, recipient_id: str = "") -> dict:
        """
        Check before sending a message in AutoGen conversation.
        """
        return self._client.gate(
            action_type = "AUTOGEN.SEND_MESSAGE",
            payload     = {"message": message[:500], "to": recipient_id},
            trust_score = self.trust_score,
        )

    def governed_reply(self, reply_func: Callable) -> Callable:
        """
        Wrap an AutoGen generate_reply function with governance.
        """
        @functools.wraps(reply_func)
        def wrapper(messages=None, sender=None, **kwargs):
            last_message = ""
            if messages:
                last_message = str(messages[-1].get("content", ""))[:500]

            result = self._client.gate(
                action_type = "AUTOGEN.GENERATE_REPLY",
                payload     = {
                    "last_message": last_message,
                    "sender":       str(sender)[:100] if sender else "",
                },
                trust_score = self.trust_score,
            )
            if not result["allowed"]:
                return f"[VeriSigil governance blocked this reply: {result['reason']}]"
            return reply_func(messages=messages, sender=sender, **kwargs)
        return wrapper


# ============================================================
# LANGGRAPH CONNECTOR
# ============================================================

class VeriSigilLangGraphNode:
    """
    LangGraph node wrapper with VeriSigil governance.

    Intercepts state transitions before node execution.
    Works with StateGraph, CompiledGraph, and custom nodes.

    Usage:
        from verisigil_connectors import VeriSigilLangGraphNode

        governed_node = VeriSigilLangGraphNode(
            api_key      = "verisigil-secret-2026",
            agent_id     = "langgraph-payment-agent",
            consequence  = "CRITICAL",
        )

        # Govern a LangGraph node function
        @governed_node.govern_node(consequence="CRITICAL")
        def payment_node(state: dict) -> dict:
            state["payment_executed"] = True
            return state

        # Add to graph
        workflow = StateGraph(dict)
        workflow.add_node("payment", payment_node)
    """

    def __init__(
        self,
        api_key:     str,
        agent_id:    str  = "langgraph-agent",
        consequence: str  = "HIGH",
        jurisdiction:str  = "GLOBAL",
        trust_score: float= 0.963,
        raise_on_deny:bool= True,
    ):
        self._client = _GovernanceClient(
            api_key=api_key, agent_id=agent_id,
            consequence=consequence, jurisdiction=jurisdiction
        )
        self.trust_score   = trust_score
        self.raise_on_deny = raise_on_deny
        self.agent_id      = agent_id

    def govern_node(
        self,
        consequence: str  = None,
        action_type: str  = None,
        trust_score: float= None,
        state_keys:  list = None,
    ) -> Callable:
        """
        Decorator for LangGraph node functions.

        Intercepts state before node executes.
        On DENY: injects governance_denied=True into state.
        On ALLOW: executes node normally.

        Usage:
            @governed_node.govern_node(
                consequence="CRITICAL",
                state_keys=["amount", "recipient"],
            )
            def execute_payment(state: dict) -> dict:
                ...
        """
        def decorator(func: Callable):
            _action = action_type or f"LANGGRAPH.{func.__name__.upper()}"
            _cons   = consequence or self._client.consequence
            _trust  = trust_score or self.trust_score
            _keys   = state_keys or []

            @functools.wraps(func)
            def wrapper(state: dict) -> dict:
                # Extract relevant state fields for governance check
                payload = {"node": func.__name__}
                for key in _keys:
                    if key in state:
                        payload[key] = str(state[key])[:200]
                if not _keys:
                    payload["state_keys"] = list(state.keys())[:10]

                result = self._client.gate(
                    action_type = _action,
                    payload     = payload,
                    trust_score = _trust,
                    consequence = _cons,
                )

                if not result["allowed"]:
                    logger.warning(
                        f"VeriSigil blocked LangGraph node {func.__name__}: "
                        f"{result['reason']}"
                    )
                    if self.raise_on_deny:
                        raise GovernanceDenied(
                            result["decision"], result["reason"],
                            self.agent_id, _action
                        )
                    # Inject denial into state instead of raising
                    return {
                        **state,
                        "governance_denied":   True,
                        "governance_decision": result["decision"],
                        "governance_reason":   result["reason"],
                        "governance_agent":    self.agent_id,
                    }

                # Node allowed — execute normally
                result_state = func(state)

                # Inject governance approval into state
                if isinstance(result_state, dict):
                    result_state["governance_allowed"] = True
                    result_state["governance_decision"] = result["decision"]

                return result_state

            return wrapper
        return decorator

    def govern_edge(
        self,
        from_node:   str,
        to_node:     str,
        consequence: str  = None,
    ) -> Callable:
        """
        Govern a LangGraph conditional edge.

        Usage:
            workflow.add_conditional_edges(
                "router",
                governed_node.govern_edge("router", "payment", consequence="CRITICAL")(
                    lambda state: "payment" if state["amount"] > 1000 else "low_value"
                )
            )
        """
        def decorator(edge_func: Callable):
            _cons = consequence or self._client.consequence

            @functools.wraps(edge_func)
            def wrapper(state: dict) -> str:
                result = self._client.gate(
                    action_type = f"LANGGRAPH.EDGE.{from_node.upper()}_TO_{to_node.upper()}",
                    payload     = {"from": from_node, "to": to_node,
                                   "state_keys": list(state.keys())[:10]},
                    trust_score = self.trust_score,
                    consequence = _cons,
                )
                if not result["allowed"]:
                    logger.warning(f"VeriSigil blocked edge {from_node}→{to_node}")
                    return "governance_denied"
                return edge_func(state)
            return wrapper
        return decorator


# ============================================================
# UNIVERSAL DECORATOR
# ============================================================

def govern(
    api_key:     str  = None,
    agent_id:    str  = "governed-agent",
    action_type: str  = None,
    consequence: str  = "HIGH",
    jurisdiction:str  = "GLOBAL",
    trust_score: float= 0.963,
    raise_on_deny:bool= True,
) -> Callable:
    """
    Universal VeriSigil governance decorator.
    Works with any Python function — framework agnostic.

    Usage:
        from verisigil_connectors import govern

        @govern(
            api_key     = "verisigil-secret-2026",
            agent_id    = "payment-agent-001",
            consequence = "CRITICAL",
            jurisdiction= "EU",
        )
        def execute_payment(amount: float, recipient: str) -> str:
            return stripe.charge(amount, recipient)

        # VeriSigil checks BEFORE execute_payment runs
        # On DENY: raises GovernanceDenied
        # On ALLOW: function runs normally
    """
    _key = api_key or os.environ.get("VERISIGIL_API_KEY", "")
    client = _GovernanceClient(
        api_key=_key, agent_id=agent_id,
        consequence=consequence, jurisdiction=jurisdiction
    )

    def decorator(func: Callable):
        _action = action_type or f"GOVERNED.{func.__name__.upper()}"

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result = client.gate(
                action_type = _action,
                payload     = {
                    "function": func.__name__,
                    "args":     str(args)[:300],
                    "kwargs":   str(kwargs)[:300],
                },
                trust_score = trust_score,
            )
            if not result["allowed"]:
                logger.warning(f"VeriSigil blocked {func.__name__}: {result['reason']}")
                if raise_on_deny:
                    raise GovernanceDenied(
                        result["decision"], result["reason"], agent_id, _action
                    )
                return None
            return func(*args, **kwargs)

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            result = await client.agate(
                action_type = _action,
                payload     = {"args": str(args)[:300], "kwargs": str(kwargs)[:300]},
                trust_score = trust_score,
            )
            if not result["allowed"]:
                if raise_on_deny:
                    raise GovernanceDenied(
                        result["decision"], result["reason"], agent_id, _action
                    )
                return None
            return await func(*args, **kwargs)

        import asyncio
        return async_wrapper if asyncio.iscoroutinefunction(func) else wrapper

    return decorator


# ============================================================
# QUICK START HELPERS
# ============================================================

def langchain_tool(
    api_key:     str,
    agent_id:    str  = "langchain-agent",
    consequence: str  = "HIGH",
) -> Callable:
    """Quick decorator for LangChain tool functions."""
    return governed_langchain_tool if _HAS_LANGCHAIN else govern(
        api_key=api_key, agent_id=agent_id, consequence=consequence
    )


def crewai_agent(
    api_key:     str,
    agent_id:    str = "crewai-agent",
    consequence: str = "HIGH",
) -> VeriSigilCrewAIAgent:
    """Quick factory for CrewAI governed agent."""
    return VeriSigilCrewAIAgent(
        api_key=api_key, agent_id=agent_id, consequence=consequence
    )


def autogen_agent(
    api_key:     str,
    agent_id:    str = "autogen-agent",
    consequence: str = "HIGH",
) -> VeriSigilAutoGenAgent:
    """Quick factory for AutoGen governed agent."""
    return VeriSigilAutoGenAgent(
        api_key=api_key, agent_id=agent_id, consequence=consequence
    )


def langgraph_node(
    api_key:     str,
    agent_id:    str = "langgraph-agent",
    consequence: str = "HIGH",
) -> VeriSigilLangGraphNode:
    """Quick factory for LangGraph governed node."""
    return VeriSigilLangGraphNode(
        api_key=api_key, agent_id=agent_id, consequence=consequence
    )


# ============================================================
# EXPORTS
# ============================================================
__all__ = [
    # Core
    "govern",
    "GovernanceDenied",
    "HumanApprovalRequired",
    "VeriSigilConnectorError",
    # LangChain
    "VeriSigilLangChainTool",
    "governed_langchain_tool",
    "langchain_tool",
    # CrewAI
    "VeriSigilCrewAIAgent",
    "crewai_agent",
    # AutoGen
    "VeriSigilAutoGenAgent",
    "autogen_agent",
    # LangGraph
    "VeriSigilLangGraphNode",
    "langgraph_node",
    # Version
    "CONNECTOR_VERSION",
]
