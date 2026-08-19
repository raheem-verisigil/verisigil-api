"""
VeriSigil "First 5 Minutes" Demo
Usage:
    python -m verisigil.demo financial-agent
    python -m verisigil.demo financial-agent --action transfer_250k
    python -m verisigil.demo medical-agent --action treatment_change
"""

import sys
import time
import json
import hashlib
import urllib.request
import urllib.error
from datetime import datetime, timezone

API_BASE = "https://verisigil-api-production.up.railway.app"
API_KEY  = "verisigil-demo-key"

COLORS = {
    "green":  "\033[92m",
    "red":    "\033[91m",
    "amber":  "\033[93m",
    "blue":   "\033[94m",
    "cyan":   "\033[96m",
    "white":  "\033[97m",
    "dim":    "\033[90m",
    "bold":   "\033[1m",
    "reset":  "\033[0m",
}

def c(color, text):
    return f"{COLORS.get(color,'')}{text}{COLORS['reset']}"

def sep():
    print(c("dim", "─" * 60))

def call_api(path, payload=None, method="POST"):
    url  = f"{API_BASE}{path}"
    data = json.dumps(payload or {}).encode() if payload else None
    req  = urllib.request.Request(
        url, data=data,
        headers={"x-api-key": API_KEY, "Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            return json.loads(resp.read()), True
    except Exception:
        return None, False


def simulate_issue(agent_name, jurisdiction="EU"):
    ts = datetime.now(timezone.utc).isoformat()
    h  = hashlib.sha256(f"{agent_name}{ts}".encode()).hexdigest()
    return {
        "passport_id":  f"vsa-{h[:10]}",
        "did":          f"did:web:verisigilai.com:agents:{agent_name}",
        "agent_id":     f"{agent_name}-sim",
        "trust_score":  0.97,
        "compliance_status": {"EU_AI_Act": "LIMITED_RISK"} if jurisdiction == "EU" else {"GLOBAL": "BASELINE"},
        "simulated": True,
    }

def simulate_verify(action_type, amount=0):
    human_only = any(h in action_type.lower() for h in ["employment","terminate","medical","military","lethal"])
    high_value = amount > 10000
    if human_only:
        verdict, reason = "REQUIRE_HUMAN_APPROVAL", "Human-only category — constitutional HAL block"
    elif high_value:
        verdict, reason = "DENY", f"Amount ${amount:,.0f} exceeds autonomous limit"
    elif "transfer" in action_type.lower() and amount > 0:
        verdict, reason = "DENY", "High-value transfer requires human escalation"
    else:
        verdict, reason = "ALLOW", "Action is constitutionally admissible"
    h = hashlib.sha256(f"{action_type}{verdict}".encode()).hexdigest()
    return {"verdict": verdict, "reason": reason, "evidence_hash": h, "rollback_available": verdict != "ALLOW", "simulated": True}


def run_demo(agent_name=None, action=None):
    agent_name = agent_name or "financial-agent"
    print()
    print(c("bold", c("white", "  VeriSigil AI — Constitutional Gateway Demo")))
    print(c("dim",  "  Intelligence scales. Legitimacy is verified."))
    print()
    sep()

    # STEP 1 — Issue Passport
    print(c("bold", "\n  STEP 1 — Issue Cryptographic Passport\n"))
    print(c("dim", f"  $ vs.issue_passport('{agent_name}', 'compliance@bank.com', 'langchain')"))
    print()

    t0      = time.time()
    payload = {"agent_name": agent_name, "owner": "compliance@bank.com", "framework": "langchain", "jurisdiction": ["EU"]}
    data, live = call_api("/v1/constitutional-gateway/issue", payload)
    latency = int((time.time() - t0) * 1000)

    if not data:
        data = simulate_issue(agent_name)

    tag = c("green", "[LIVE API]") if live else c("dim", "[SIMULATED]")
    print(f"  {c('green','✅')} Passport issued {tag}")
    print(f"  {c('dim','passport_id:')} {c('cyan', data.get('passport_id','—'))}")
    print(f"  {c('dim','did:')}         {c('cyan', data.get('did','—'))}")
    print(f"  {c('dim','trust_score:')} {c('green', str(data.get('trust_score', 0.97)))}")

    cs = data.get("compliance_status", {})
    for k, v in cs.items():
        print(f"  {c('dim', k+':')} {c('green', v)}")

    passport_id = data.get("passport_id", "vsa-demo")
    print()
    sep()

    # STEP 2 — Verify Action
    ACTION_MAP = {
        "transfer_250k":    {"type": "wire_transfer",          "amount": 250000},
        "treatment_change": {"type": "medical_treatment_change","amount": 0},
        "loan_approval":    {"type": "loan_approval",           "amount": 50000},
        "terminate_emp":    {"type": "terminate_employment",    "amount": 0},
        "query_status":     {"type": "query_agent_status",      "amount": 0},
        "report":           {"type": "generate_compliance_report","amount": 0},
    }
    action_key  = (action or "").lstrip("-").replace("--action=","").replace("--action","").strip()
    action_data = ACTION_MAP.get(action_key, {"type": "query_agent_status", "amount": 0})

    print(c("bold", f"\n  STEP 2 — Verify Before Action\n"))
    print(c("dim", "  $ vs.verify_before_action(passport_id, action)\n"))

    t0      = time.time()
    vpayload= {"passport_id": passport_id, "action": action_data, "context": {"jurisdiction": "EU", "consequence": "HIGH" if action_data["amount"] > 10000 else "MEDIUM"}}
    vdata, vlive = call_api("/v1/constitutional-gateway/verify", vpayload)
    vlatency= int((time.time() - t0) * 1000)

    if not vdata:
        vdata = simulate_verify(action_data["type"], action_data["amount"])

    verdict = vdata.get("verdict", "DENY")
    vtag    = c("green", "[LIVE API]") if vlive else c("dim", "[SIMULATED]")

    if verdict == "ALLOW":
        print(f"  {c('green','✅')} {c('bold', c('green','ALLOW'))} {vtag}")
    elif verdict == "DENY":
        print(f"  {c('red','⛔')} {c('bold', c('red','DENIED'))} {vtag}")
    else:
        print(f"  {c('amber','⚠️')} {c('bold', c('amber','REQUIRE HUMAN APPROVAL'))} {vtag}")

    print(f"  {c('dim','reason:')}    {vdata.get('reason','—')}")
    print(f"  {c('dim','rollback:')} {c('green','available') if vdata.get('rollback_available') else c('dim','n/a')}")

    evidence_hash = vdata.get("evidence_hash","")
    exec_id       = vdata.get("execution_id", f"exec-demo-{agent_name}")

    print()
    sep()

    # STEP 3 — Export Evidence
    print(c("bold", "\n  STEP 3 — Export Cryptographic Evidence\n"))
    print(c("dim", "  $ vs.export_evidence_bundle(execution_id)\n"))

    t0     = time.time()
    epay   = {"execution_id": exec_id, "agent_id": data.get("agent_id",""), "formats": ["json"]}
    edata, elive  = call_api("/v1/constitutional-gateway/prove", epay)
    elatency= int((time.time() - t0) * 1000)

    etag   = c("green", "[LIVE API]") if elive else c("dim", "[SIMULATED]")
    bundle = edata.get("bundle_id","bundle-demo") if edata else "bundle-demo"
    ehash  = edata.get("bundle_hash", evidence_hash) if edata else evidence_hash

    print(f"  {c('green','✅')} Evidence sealed {etag}")
    print(f"  {c('dim','bundle_id:')}   {c('cyan', bundle)}")
    print(f"  {c('dim','hash:')}        {c('cyan', ehash[:32]+'...')}")
    print(f"  {c('dim','verifiable:')} {c('green','offline — SHA-256 — no platform access required')}")
    print(f"  {c('dim','doi_ref:')}    {c('dim','10.5281/zenodo.20451306')}")
    print()
    sep()

    # RESILIENCE SCORE
    print(c("bold", "\n  BONUS — Constitutional Resilience Score\n"))
    print(c("dim", f"  $ curl .../v1/constitutional-gateway/resilience/{passport_id}\n"))

    t0     = time.time()
    rdata, rlive = call_api(f"/v1/constitutional-gateway/resilience/{passport_id}", method="GET")
    rlatency= int((time.time() - t0) * 1000)

    if not rdata:
        rdata = {"resilience_score": 0.94, "verdict": "CONSTITUTIONALLY_RESILIENT",
                 "components": {"boundary_enforcement":0.98,"evidence_integrity":0.96,"human_sovereignty":0.92,"regulatory_alignment":0.90,"adversarial_resistance":0.95}}

    rtag   = c("green","[LIVE API]") if rlive else c("dim","[SIMULATED]")
    score  = rdata.get("resilience_score", 0.94)
    rverdict= rdata.get("verdict","CONSTITUTIONALLY_RESILIENT")

    print(f"  {c('green','✅')} {c('bold', c('green', rverdict))} {rtag}")
    print(f"  {c('dim','resilience_score:')} {c('bold', c('green', str(score)))}/1.00")
    for k, v in rdata.get("components",{}).items():
        bar = "█" * int(float(v)*10) + "░" * (10 - int(float(v)*10))
        print(f"  {c('dim', f'{k}:')} {c('cyan', bar)} {v}")

    print()
    sep()
    print()
    print(c("bold", c("white", "  Summary")))
    print(f"  {c('green','✅')} Passport:   {c('cyan', data.get('passport_id','—'))}")
    print(f"  {c('green' if verdict=='ALLOW' else 'red','  ✅' if verdict=='ALLOW' else '  ⛔')} Decision:   {c('green' if verdict=='ALLOW' else 'red', verdict)}")
    print(f"  {c('green','✅')} Evidence:   {c('cyan', ehash[:24]+'...')}")
    print(f"  {c('green','✅')} Resilience: {c('green', str(score))}/1.00 — {rverdict}")
    print()
    print(c("dim", "  Next: https://verisigilai.com/pricing.html"))
    print(c("dim", "  Docs: https://verisigil-api-production.up.railway.app/docs"))
    print()


def main():
    args       = sys.argv[1:]
    agent_name = args[0] if args else "financial-agent"
    action     = None
    for i, a in enumerate(args):
        if a == "--action" and i+1 < len(args):
            action = args[i+1]
        elif a.startswith("--action="):
            action = a.split("=",1)[1]
    run_demo(agent_name, action)


if __name__ == "__main__":
    main()
