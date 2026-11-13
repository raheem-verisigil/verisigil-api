"""Bounded staging adversarial validation for Terry's three proposed scenarios."""
import os
from datetime import datetime, timedelta, timezone

os.environ.setdefault("SUPABASE_URL", "http://127.0.0.1:1")
os.environ.setdefault("SUPABASE_KEY", "verisigil-test-only-not-a-credential")
os.environ.setdefault("VERISIGIL_API_KEY", "verisigil-test-api-key-only")
os.environ.setdefault("SIGN_SECRET", "verisigil-test-signing-secret-not-for-deployment")
os.environ.setdefault("DEPLOY_ENV", "test")

from fastapi.testclient import TestClient
import main as core
import verisigil_entrypoint as runtime

client = TestClient(runtime.app)
API = {"x-api-key": os.environ["VERISIGIL_API_KEY"]}


async def _no_persist(*args, **kwargs):
    return None


def _capacity_assertion(state):
    response = client.post("/v1/state-assertions", headers=API, json={
        "issuer": "terry-bounded-test-fixture",
        "subject": "synthetic-resource-pool",
        "state_type": "capacity",
        "state": state,
        "source_version": "fixture-v1",
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
        "freshness_seconds": 600,
    })
    assert response.status_code == 200, response.text
    return response.json()


def _delegate(agent_id):
    response = client.post("/v1/delegation/passport", headers=API, json={
        "agent_id": agent_id, "org_id": "terry-test-org",
        "allowed_actions": ["TRANSFER"], "forbidden_actions": ["DELETE_LEDGER"],
        "budget": 1000, "max_transaction_value": 1000,
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
    })
    assert response.status_code == 200, response.text
    return response.json()


def _proposal(agent_id, assertion):
    response = client.post("/v1/proposals", headers=API, json={
        "tenant_id": "terry-test-tenant", "governance_domain": "synthetic-finance",
        "environment": "staging", "agent_id": agent_id, "action_type": "TRANSFER",
        "target": "synthetic-ledger-account", "parameters": {"amount": 100, "currency": "USD"},
        "decision_outcome": "ALLOW_PENDING_COMMIT_TIME_REVALIDATION",
        "policy_id": "terry-test-policy", "policy_version": "1.0",
        "state_assertion_id": assertion["assertion_id"], "state_root": assertion["state_root"],
        "authority_root": "test-authority-root",
    })
    assert response.status_code == 200, response.text
    return response.json()


def _revalidate(proposal, agent_id, assertion_id):
    response = client.post("/v1/revalidation/check", headers=API, json={
        "proposal_id": proposal["proposal_id"], "proposal_hash": proposal["proposal_hash"],
        "target": "synthetic-ledger-account", "parameters": {"amount": 100, "currency": "USD"},
        "agent_id": agent_id, "action_type": "TRANSFER",
        "capacity_assertion_id": assertion_id, "required_capacity": 100, "amount": 100,
    })
    assert response.status_code == 200, response.text
    return response.json()


def _verify_receipt(receipt):
    unsigned = dict(receipt)
    signature = unsigned.pop("governance_signature")
    key = client.get("/v1/proof/public-key").json()
    from proof_verification import public_key_id
    response = client.post("/v1/proof/verify", params={
        "signature": signature, "key_id": public_key_id(key["public_key"]),
    }, json=unsigned)
    assert response.status_code == 200, response.text
    assert response.json()["result"] == "VERIFIED", response.json()


def test_terry_three_stage_adversarial_validation_and_replayable_receipts(monkeypatch):
    monkeypatch.setattr(core, "_vgs_persist", _no_persist)
    core._STATE_ASSERTIONS.clear()
    core._PROPOSAL_REGISTRY.clear()
    core._DELEGATION_PASSPORTS.clear()
    core._REVALIDATION_LOG.clear()
    runtime.VALIDATION_RECEIPTS.clear()

    agent = "terry-capacity-agent"
    initial = _capacity_assertion({
        "capacity": {"total": 160, "available": 130, "required": 100},
        "obligations": [{"id": "existing-obligation-001", "amount": 30}],
    })
    _delegate(agent)
    proposal = _proposal(agent, initial)

    baseline = _revalidate(proposal, agent, initial["assertion_id"])
    assert baseline["ruling"] == "ALLOW"
    assert baseline["capacity"]["cumulative_obligations"] == 30
    _verify_receipt(baseline)

    revoked = client.post(f"/v1/delegation/passport/revoke/{agent}", headers=API, json={
        "reason": "Terry scenario: authority revoked after proposal",
    })
    assert revoked.status_code == 200, revoked.text
    _verify_receipt(revoked.json())

    stale_auth = client.post("/v1/execution/authorize", headers=API, json={
        "proposal_id": proposal["proposal_id"], "revalidation_id": baseline["revalidation_id"],
        "ttl_seconds": 30,
    })
    assert stale_auth.status_code == 403, stale_auth.text
    assert stale_auth.json()["allowed"] is False
    assert stale_auth.json()["ruling"] == "AUTHORITY_INVALID"
    _verify_receipt(stale_auth.json())

    _delegate(agent)
    contradictory = _capacity_assertion({
        "capacity": {"total": 100, "available": 80, "required": 100},
        "obligations": [{"id": "existing-obligation-001", "amount": 30}],
    })
    stale_after_reissue = client.post("/v1/execution/authorize", headers=API, json={
        "proposal_id": proposal["proposal_id"], "revalidation_id": baseline["revalidation_id"],
        "ttl_seconds": 30,
    })
    assert stale_after_reissue.status_code == 403, stale_after_reissue.text
    _verify_receipt(stale_after_reissue.json())

    refused = _revalidate(proposal, agent, contradictory["assertion_id"])
    assert refused["ruling"] == "CAPACITY_CONTRADICTION"
    assert refused["allowed"] is False
    assert refused["capacity"]["cumulative_obligations"] == 30
    _verify_receipt(refused)

    refused_auth = client.post("/v1/execution/authorize", headers=API, json={
        "proposal_id": proposal["proposal_id"], "revalidation_id": refused["revalidation_id"],
        "ttl_seconds": 30,
    })
    assert refused_auth.status_code == 403, refused_auth.text
    _verify_receipt(refused_auth.json())

    restored = _capacity_assertion({
        "capacity": {"total": 160, "available": 130, "required": 100},
        "obligations": [{"id": "existing-obligation-001", "amount": 30}],
    })
    continued = _revalidate(proposal, agent, restored["assertion_id"])
    assert continued["ruling"] == "ALLOW"
    assert continued["capacity"]["cumulative_obligations"] == 30
    assert continued["checks"]["cumulative_obligations_accounted"] is True
    _verify_receipt(continued)

    execution = client.post("/v1/execution/authorize", headers=API, json={
        "proposal_id": proposal["proposal_id"], "revalidation_id": continued["revalidation_id"],
        "ttl_seconds": 30,
    })
    assert execution.status_code == 200, execution.text
    execution_receipt = execution.json()
    assert execution_receipt["commit_time_recheck"]["capacity"]["cumulative_obligations"] == 30
    assert execution_receipt["consequence_boundary"] == "PRE_EXECUTION_AUTHORIZATION_ONLY"
    assert execution_receipt["expires_at"] > execution_receipt["issued_at"]
    _verify_receipt(execution_receipt)
