# VeriSigil AI — Developer Quickstart
# 5 minutes from zero to governed AI agent

## What VeriSigil Does

VeriSigil provides execution legitimacy infrastructure for autonomous AI systems.

It verifies whether AI execution was admissible before consequence occurred,
preserves governance continuity during runtime, and produces replayable
cryptographic evidence for enterprise and regulatory environments.

---

## Option 1: Use the Live API (Fastest — 30 seconds)

```bash
# Your API key
export VERISIGIL_API_KEY="verisigil-secret-2026"
export VERISIGIL_URL="https://verisigil-api-production.up.railway.app"

# Test governance gate
curl -X POST "$VERISIGIL_URL/v1/execution/control" \
  -H "x-api-key: $VERISIGIL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "my-first-agent",
    "action_type": "PAYMENT_EXECUTION",
    "trust_score": 0.963,
    "consequence": "CRITICAL",
    "jurisdiction": "EU"
  }'
```

Expected response:
```json
{
  "decision": "REQUIRE_HUMAN_APPROVAL",
  "reason": "CRITICAL consequence requires human oversight",
  "human_readable": "Action blocked — human approval required"
}
```

---

## Option 2: Python SDK (2 minutes)

```bash
pip install requests
```

```python
# quickstart.py
import requests
import os

VERISIGIL_URL = os.environ.get("VERISIGIL_URL", "https://verisigil-api-production.up.railway.app")
VERISIGIL_KEY = os.environ.get("VERISIGIL_API_KEY", "verisigil-secret-2026")

headers = {
    "x-api-key": VERISIGIL_KEY,
    "Content-Type": "application/json"
}

# Step 1: Register your agent
print("Step 1: Registering agent...")
r = requests.post(f"{VERISIGIL_URL}/v1/identity/birth-certificate", headers=headers, json={
    "agent_id":        "quickstart-agent-001",
    "creator_id":      "developer@mycompany.com",
    "organization":    "My Company",
    "jurisdiction":    "EU",
    "capability_class":"FINANCIAL",
    "purpose":         "Payment processing governance"
})
cert = r.json()
print(f"  Birth certificate: {cert['cert_id']}")
print(f"  Autonomy ceiling: {cert['autonomy_ceiling']}")

# Step 2: Check governance before executing
print("\nStep 2: Checking governance...")
r = requests.post(f"{VERISIGIL_URL}/v1/execution/control", headers=headers, json={
    "agent_id":    "quickstart-agent-001",
    "action_type": "PAYMENT_EXECUTION",
    "trust_score": 0.963,
    "consequence": "HIGH",
    "jurisdiction":"EU"
})
gate = r.json()
print(f"  Decision: {gate.get('decision') or gate.get('governance_decision')}")

# Step 3: Compute Execution Trust Score
print("\nStep 3: Computing trust score...")
r = requests.post(f"{VERISIGIL_URL}/v1/execution/trust-score", headers=headers, json={
    "agent_id":             "quickstart-agent-001",
    "action_type":          "PAYMENT_EXECUTION",
    "trust_score":          0.963,
    "consequence":          "HIGH",
    "jurisdiction":         "EU",
    "identity_verified":    True,
    "temporal_validity":    True,
    "oversight_confidence": 0.85,
})
ets = r.json()
print(f"  ETS: {ets['execution_trust_score']}/100 — {ets['ets_band']}")
print(f"  Insurable: {ets['insurable']} ({ets['insurance_tier']})")

# Step 4: Check human authority (HAL)
print("\nStep 4: Checking human authority layer...")
r = requests.post(f"{VERISIGIL_URL}/v1/human/authority/check", headers=headers, json={
    "agent_id":    "quickstart-agent-001",
    "action_type": "fire_employee",
    "domain":      "hr",
    "consequence": "CRITICAL"
})
hal = r.json()
print(f"  Action: fire_employee")
print(f"  Decision: {hal['decision']}")
print(f"  Human required: {hal['human_required']}")
print(f"  Board language: {hal['board_language']}")

# Step 5: Get sovereignty status
print("\nStep 5: Sovereignty status...")
r = requests.get(f"{VERISIGIL_URL}/v1/human/sovereignty/status", headers=headers)
sov = r.json()
print(f"  Posture: {sov['sovereignty_posture']}")
print(f"  Layers active: {len(sov['layers'])}")

print("\n✅ Quickstart complete. VeriSigil governance is working.")
print(f"\nAPI docs: {VERISIGIL_URL}/docs")
print(f"Category: https://verisigilai.com/category")
```

Run it:
```bash
python quickstart.py
```

---

## Option 3: @govern Decorator (1 line)

```python
# decorator_example.py
import sys
sys.path.insert(0, '.')
from verisigil_sdk import VeriSigil, govern

# Configure once
vs = VeriSigil(api_key="verisigil-secret-2026")

# Add governance to any function
@govern(consequence="CRITICAL", domain="finance")
def execute_payment(amount: float, recipient: str):
    """This function is now governed by VeriSigil."""
    print(f"Executing payment: ${amount} to {recipient}")
    return {"status": "executed", "amount": amount}

# @govern checks governance before execution
# If denied → raises GovernanceDenied
# If approved → function runs normally
try:
    result = execute_payment(50000, "vendor@company.com")
    print(result)
except Exception as e:
    print(f"Governance denied: {e}")
```

---

## Option 4: Docker Local Deployment (5 minutes)

```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY main.py .
COPY verisigil_sdk.py .

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

```txt
# requirements.txt
fastapi==0.115.0
uvicorn==0.30.0
pydantic==2.0.0
httpx==0.27.0
supabase==2.0.0
requests==2.31.0
```

```bash
# Build and run locally
docker build -t verisigil-local .
docker run -p 8000:8000 \
  -e VERISIGIL_API_KEY=verisigil-secret-2026 \
  -e SUPABASE_URL=your-supabase-url \
  -e SUPABASE_KEY=your-supabase-key \
  verisigil-local

# Test local deployment
curl http://localhost:8000/health
```

---

## Option 5: LangChain Integration (3 minutes)

```python
# langchain_example.py
from verisigil_sdk import VeriSigil, LangChainConnector

vs         = VeriSigil(api_key="verisigil-secret-2026")
connector  = LangChainConnector(client=vs)

@connector.govern_tool("payment_tool", consequence="CRITICAL")
def payment_tool(amount: float, recipient: str) -> str:
    """LangChain tool — now governed by VeriSigil."""
    return f"Payment of ${amount} to {recipient} executed"

# Tool is now governed — VeriSigil checks before every call
result = payment_tool(1000, "vendor@company.com")
print(result)
```

---

## Option 6: VSL Governance Script (2 minutes)

```python
# vsl_example.py
import requests

headers = {"x-api-key": "verisigil-secret-2026", "Content-Type": "application/json"}
url     = "https://verisigil-api-production.up.railway.app"

# Write a governance script in VSL
vsl_script = """
IDENTITY agent: treasury-ai
AUTHORITY finance.l3
CONCURRENCE 2_of_3
ACTION wire_transfer AMOUNT 500000
REQUIRES compliance.approved
REQUIRES jurisdiction.eu_valid
TRACE immutable
EVIDENCE cryptographic
"""

# Parse the script
r = requests.post(f"{url}/v1/vsl/parse",
    headers=headers,
    json={"agent_id": "treasury-ai", "script": vsl_script})

parsed = r.json()
print(f"Valid: {parsed['valid']}")
print(f"Action: {parsed['parsed']['action']}")
print(f"Concurrence: {parsed['parsed']['concurrence']}")
print(f"Preconditions: {len(parsed['parsed']['requires'])}")
print(f"VGS mapping: {list(parsed['vgs_mapping'].keys())}")
```

---

## The One Sentence

**VeriSigil AI provides execution legitimacy infrastructure for autonomous systems.**

It verifies whether AI execution was admissible before consequence occurred,
preserves governance continuity during runtime, and produces replayable
cryptographic evidence for enterprise and regulatory environments.

---

## Key Endpoints (Start Here)

| What | Endpoint | Why |
|---|---|---|
| Governance gate | `POST /v1/execution/control` | Check before every agent action |
| Register agent | `POST /v1/identity/birth-certificate` | Establish agent identity |
| Trust score | `POST /v1/execution/trust-score` | Insurable, auditable ETS |
| HAL check | `POST /v1/human/authority/check` | 8 human-only categories |
| Sovereignty | `GET /v1/human/sovereignty/status` | All 6 layers |
| Health | `GET /health` | Is system alive? |
| EU AI Act | `GET /v1/compliance/eu-ai-act` | Regulatory mapping |

---

## Full API Documentation

```
https://verisigil-api-production.up.railway.app/docs
```

## Category Definition

```
https://verisigilai.com/category
```

## Support

```
raheem@verisigilai.com
```
