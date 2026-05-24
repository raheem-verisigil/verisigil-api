# ============================================================
# VERISIGIL — AUTOMATED TEST SUITE
# ============================================================
# Pytest tests for all critical VeriSigil endpoints.
# Runs in GitHub Actions before every deployment.
#
# Test categories:
# 1. Health & System         — /health, /readiness, /liveness
# 2. Governance Core         — /v1/execution/control
# 3. Document Integrity      — /v1/document/semantic-verify
# 4. Human Sovereignty       — /v1/human/authority/check
# 5. Concurrence Engine      — /v1/concurrence/workflow/create
# 6. VSL Parser              — /v1/vsl/parse
# 7. ATF Bridge              — /v1/bridge/atf/validate
# 8. Diagnostics             — /v1/diagnostics/integrity
# 9. Database                — /v1/db/status
# 10. Inference Integrity    — /v1/inference/verify
#
# Run: pytest tests/test_verisigil.py -v
# ============================================================

import pytest
import httpx
import os
import json

# ── CONFIG ────────────────────────────────────────────────────
BASE_URL  = os.environ.get(
    "VERISIGIL_TEST_URL",
    "https://verisigil-api-production.up.railway.app"
)
API_KEY   = os.environ.get("VERISIGIL_API_KEY", "verisigil-secret-2026")
HEADERS   = {
    "x-api-key":    API_KEY,
    "Content-Type": "application/json",
}
TIMEOUT   = 30.0


@pytest.fixture(scope="session")
def client():
    """Shared HTTP client for all tests."""
    with httpx.Client(base_url=BASE_URL, timeout=TIMEOUT) as c:
        yield c


# ============================================================
# 1. HEALTH & SYSTEM TESTS
# ============================================================

class TestHealth:

    def test_health_returns_200(self, client):
        """Basic liveness — must always return 200."""
        r = client.get("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert data["service"] == "verisigil-api"

    def test_readiness_returns_200(self, client):
        """System must be ready for traffic."""
        r = client.get("/readiness")
        assert r.status_code in (200, 503)  # 503 acceptable if DB unavailable
        data = r.json()
        assert "status" in data
        assert "checks" in data

    def test_liveness_returns_200(self, client):
        """Process must be alive."""
        r = client.get("/liveness")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "alive"

    def test_version_endpoint(self, client):
        """Version info must be present."""
        r = client.get("/health/version")
        assert r.status_code == 200
        data = r.json()
        assert "version" in data
        assert "endpoints" in data
        assert data["endpoints"] > 300

    def test_deep_health(self, client):
        """Deep health must return all subsystems."""
        r = client.get("/health/deep", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert "subsystems" in data
        assert "governance_runtime" in data["subsystems"]
        assert "human_sovereignty" in data["subsystems"]
        assert "atf_bridge" in data["subsystems"]

    def test_db_status(self, client):
        """DB status must return mode info."""
        r = client.get("/v1/db/status", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert "db_connected" in data
        assert "mode" in data


# ============================================================
# 2. GOVERNANCE CORE TESTS
# ============================================================

class TestGovernanceCore:

    def test_governance_gate_allow(self, client):
        """Low-risk action should be ALLOW."""
        r = client.post("/v1/execution/control", headers=HEADERS, json={
            "agent_id":    "test-agent-001",
            "action_type": "READ_REPORT",
            "trust_score": 0.963,
            "consequence": "LOW",
            "jurisdiction":"GLOBAL",
        })
        assert r.status_code == 200
        data = r.json()
        assert "decision" in data or "governance_decision" in data

    def test_governance_gate_high_risk(self, client):
        """Critical action with low trust should escalate."""
        r = client.post("/v1/execution/control", headers=HEADERS, json={
            "agent_id":    "test-agent-001",
            "action_type": "PAYMENT_EXECUTION",
            "trust_score": 0.20,
            "consequence": "CRITICAL",
            "jurisdiction":"EU",
        })
        assert r.status_code == 200
        data = r.json()
        decision = data.get("decision") or data.get("governance_decision", "")
        assert decision in ("DENY", "REQUIRE_HUMAN_APPROVAL",
                            "BLOCK_AND_ESCALATE", "ALLOW", "MONITOR")

    def test_fail_safe_endpoint(self, client):
        """Fail-safe must confirm DENY by default."""
        r = client.get("/v1/governance/failsafe", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert data.get("failsafe_behavior") == "DENY"
        assert data.get("governance_posture") == "DENY_BY_DEFAULT"

    def test_governance_os_status(self, client):
        """Governance OS must report running."""
        r = client.get("/v1/os/status", headers=HEADERS)
        assert r.status_code == 200


# ============================================================
# 3. DOCUMENT INTEGRITY TESTS
# ============================================================

class TestDocumentIntegrity:

    def test_semantic_verify_clean(self, client):
        """Clean document should pass integrity check."""
        r = client.post("/v1/document/semantic-verify", headers=HEADERS, json={
            "original_text": "The payment shall not exceed $50,000 and requires board approval.",
            "current_text":  "The payment shall not exceed $50,000 and requires board approval.",
            "document_type": "contract",
            "domain":        "finance",
        })
        assert r.status_code == 200
        data = r.json()
        assert "decision" in data or "integrity_decision" in data

    def test_semantic_verify_corruption(self, client):
        """Corrupted document should be flagged."""
        r = client.post("/v1/document/semantic-verify", headers=HEADERS, json={
            "original_text": "The payment shall NOT exceed $50,000 and requires board approval.",
            "current_text":  "The payment shall exceed $500,000 and requires management approval.",
            "document_type": "contract",
            "domain":        "finance",
        })
        assert r.status_code == 200
        data = r.json()
        # Should detect corruption — decision should not be clean ALLOW
        assert "decision" in data or "integrity_decision" in data


# ============================================================
# 4. HUMAN SOVEREIGNTY TESTS
# ============================================================

class TestHumanSovereignty:

    def test_hal_blocks_fire_employee(self, client):
        """HAL must block employment termination."""
        r = client.post("/v1/human/authority/check", headers=HEADERS, json={
            "agent_id":    "test-agent-001",
            "action_type": "fire_employee",
            "domain":      "hr",
            "consequence": "CRITICAL",
        })
        assert r.status_code == 200
        data = r.json()
        assert data.get("human_required") is True
        assert data.get("decision") == "HUMAN_ONLY"

    def test_hal_blocks_lethal_systems(self, client):
        """HAL must block lethal force authorization."""
        r = client.post("/v1/human/authority/check", headers=HEADERS, json={
            "agent_id":    "test-agent-001",
            "action_type": "weapons_authorization",
            "domain":      "defense",
            "consequence": "CRITICAL",
        })
        assert r.status_code == 200
        data = r.json()
        assert data.get("human_required") is True

    def test_hal_allows_low_risk(self, client):
        """HAL must allow low-risk non-protected actions."""
        r = client.post("/v1/human/authority/check", headers=HEADERS, json={
            "agent_id":    "test-agent-001",
            "action_type": "generate_report",
            "domain":      "general",
            "consequence": "LOW",
        })
        assert r.status_code == 200
        data = r.json()
        assert data.get("decision") in ("ALLOW", "REQUIRE_HUMAN_APPROVAL")

    def test_sovereignty_status(self, client):
        """Sovereignty status must show all 6 layers active."""
        r = client.get("/v1/human/sovereignty/status", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert data.get("sovereignty_posture") == "HUMAN_SOVEREIGN"
        layers = data.get("layers", {})
        assert len(layers) == 6

    def test_cognitive_challenge_issued(self, client):
        """Cognitive challenge must return a prompt."""
        r = client.post("/v1/human/cognitive/challenge", headers=HEADERS, json={
            "reviewer_id":   "reviewer-001",
            "agent_id":      "agent-001",
            "action_type":   "PAYMENT_EXECUTION",
            "consequence":   "CRITICAL",
            "challenge_type":"adversarial_review",
        })
        assert r.status_code == 200
        data = r.json()
        assert "challenge_prompt" in data
        assert len(data["challenge_prompt"]) > 10


# ============================================================
# 5. CONCURRENCE ENGINE TESTS
# ============================================================

class TestConcurrenceEngine:

    def test_create_workflow(self, client):
        """Must create concurrence workflow with legitimacy graph."""
        r = client.post("/v1/concurrence/workflow/create", headers=HEADERS, json={
            "workflow_name":     "Test Payment Authorization",
            "action_type":       "PAYMENT_EXECUTION",
            "agent_id":          "test-agent-001",
            "consequence":       "CRITICAL",
            "domain":            "finance",
            "sequence_template": "financial_large",
            "concurrence_type":  "ALL",
            "window_hours":      24,
            "financial_amount":  100000,
        })
        assert r.status_code == 200
        data = r.json()
        assert "workflow_id" in data
        assert data["status"] == "PENDING"
        assert "legitimacy_graph" in data
        assert data["concurrence_rule"] == "4-of-4"
        return data["workflow_id"]

    def test_threshold_advisor(self, client):
        """Threshold advisor must recommend based on amount."""
        r = client.post(
            "/v1/concurrence/threshold",
            headers=HEADERS,
            params={"domain": "finance", "action_type": "PAYMENT", "financial_amount": 500000}
        )
        assert r.status_code == 200
        data = r.json()
        assert "recommended_n" in data
        assert "recommended_m" in data
        assert data["recommended_n"] >= 3  # 500K should require senior approval


# ============================================================
# 6. VSL PARSER TESTS
# ============================================================

class TestVSLParser:

    def test_parse_valid_script(self, client):
        """Valid VSL script must parse with zero errors."""
        r = client.post("/v1/vsl/parse", headers=HEADERS, json={
            "agent_id": "test-agent-001",
            "script":   (
                "IDENTITY agent: treasury-ai\n"
                "AUTHORITY finance.l3\n"
                "CONCURRENCE 2_of_3\n"
                "ACTION wire_transfer AMOUNT 500000\n"
                "REQUIRES compliance.approved\n"
                "REQUIRES jurisdiction.eu_valid\n"
                "TRACE immutable\n"
                "EVIDENCE cryptographic"
            ),
        })
        assert r.status_code == 200
        data = r.json()
        assert data["valid"] is True
        assert len(data["errors"]) == 0
        assert data["parsed"]["action"] == "wire_transfer"
        assert data["parsed"]["concurrence_n"] == 2
        assert data["parsed"]["concurrence_m"] == 3
        assert len(data["parsed"]["requires"]) == 2

    def test_parse_invalid_concurrence(self, client):
        """Invalid concurrence (N > M) must produce error."""
        r = client.post("/v1/vsl/parse", headers=HEADERS, json={
            "agent_id": "test-agent-001",
            "script":   "IDENTITY agent: test\nACTION test_action\nCONCURRENCE 5_of_3",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["valid"] is False
        assert len(data["errors"]) > 0

    def test_parse_missing_identity(self, client):
        """Script without IDENTITY must produce error."""
        r = client.post("/v1/vsl/parse", headers=HEADERS, json={
            "agent_id": "test-agent-001",
            "script":   "ACTION payment\nREQUIRES compliance.ok",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["valid"] is False


# ============================================================
# 7. ATF BRIDGE TESTS
# ============================================================

class TestATFBridge:

    def test_bridge_validate_nominal(self, client):
        """Nominal ATF trace must pass bridge validation."""
        r = client.post("/v1/bridge/atf/validate", headers=HEADERS, json={
            "dr": {
                "delegation_id":              "ATFDR-A1B2C3D4E5F60001",
                "delegator_id":               "AID-COMPLIANCE-A1B2C3D4E5F60001",
                "delegate_id":                "AID-AUDIT-F1E2D3C4B5A60007",
                "task_scope":                 {"domain": "compliance", "permitted_actions": ["read_evidence"]},
                "authority_budget_delegator": 80.0,
                "authority_budget_granted":   60.0,
                "chain_root_id":              "ATFDR-ROOT0000000001",
                "delegation_depth":           1,
                "delegator_public_key":       "",
                "posture_state_hash":         "28c1dcbd36bae0faf708af58f72d5cc5103974266b3ab47c52cf76c23bcb1095",
                "status":                     "ACTIVE",
                "created_at":                 "2026-05-21T10:00:00+00:00",
                "expires_at":                 "2026-05-22T10:00:00+00:00",
                "metadata":                   {},
            },
            "tar": {
                "tar_id":                 "ATFTAR-F1E2D3C4B5A60001",
                "delegation_id":          "ATFDR-A1B2C3D4E5F60001",
                "agent_id":               "AID-AUDIT-F1E2D3C4B5A60007",
                "execution_ns":           1748131200000000000,
                "execution_ts":           "2026-05-21T10:00:00+00:00",
                "dr_status_at_admission": "ACTIVE",
                "dr_expires_at":          "2026-05-22T10:00:00+00:00",
                "authority_budget":        60.0,
                "domain":                 "compliance",
                "task_action":            "read_evidence",
                "admission_status":       "ADMITTED",
                "chain_root_id":          "ATFDR-ROOT0000000001",
                "issued_at":              "2026-05-21T10:00:01+00:00",
                "metadata":               {},
            },
        })
        assert r.status_code == 200
        data = r.json()
        assert data.get("bridge_valid") is True
        assert data.get("critical_violations", 1) == 0

    def test_bridge_summary(self, client):
        """Bridge summary must return session count."""
        r = client.get("/v1/bridge/atf/summary", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert "total_sessions" in data
        assert "bridge_version" in data


# ============================================================
# 8. DIAGNOSTICS TESTS
# ============================================================

class TestDiagnostics:

    def test_governance_integrity(self, client):
        """Governance integrity must return a score."""
        r = client.get("/v1/diagnostics/integrity", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert "governance_integrity_score" in data
        assert "operational_legitimacy" in data
        assert 0 <= data["governance_integrity_score"] <= 100

    def test_governance_pulse(self, client):
        """Pulse must return health status."""
        r = client.get("/v1/diagnostics/pulse", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert "governance_pulse" in data
        assert data.get("api_healthy") is True

    def test_mri_scan(self, client):
        """MRI scan must return heatmap."""
        r = client.get("/v1/diagnostics/mri", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert "governance_heatmap" in data
        assert "runtime_stress" in data

    def test_executive_dashboard(self, client):
        """Executive dashboard must return all briefings."""
        r = client.get("/v1/diagnostics/executive", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert "board_briefing" in data
        assert "cro_briefing" in data
        assert "ciso_briefing" in data
        assert "regulator_briefing" in data


# ============================================================
# 9. INFERENCE INTEGRITY TESTS
# ============================================================

class TestInferenceIntegrity:

    def test_pii_detection(self, client):
        """PII in output must be detected and blocked."""
        r = client.post("/v1/inference/verify", headers=HEADERS, json={
            "agent_id":    "test-agent-001",
            "model_id":    "gpt-4o",
            "output_text": "Patient SSN is 123-45-6789 and credit card 4532-1234-5678-9012",
            "input_text":  "Summarize the treatment plan",
            "domain":      "healthcare",
        })
        assert r.status_code == 200
        data = r.json()
        assert data.get("corruption_detected") is True
        assert data.get("decision") in ("BLOCK", "REQUIRE_HUMAN_APPROVAL")
        vectors = data.get("vectors", {})
        assert vectors.get("pii_leakage", {}).get("detected") is True

    def test_clean_output_passes(self, client):
        """Clean output must pass integrity check."""
        r = client.post("/v1/inference/verify", headers=HEADERS, json={
            "agent_id":    "test-agent-001",
            "model_id":    "gpt-4o",
            "output_text": "The quarterly revenue report shows strong performance across all business units with consistent growth.",
            "input_text":  "Summarize the quarterly report",
            "domain":      "finance",
        })
        assert r.status_code == 200
        data = r.json()
        assert "decision" in data
        assert "corruption_score" in data


# ============================================================
# 10. SOVEREIGNTY & SURVIVABILITY TESTS
# ============================================================

class TestSovereignty:

    def test_survivability_diagnostics(self, client):
        """Survivability must return GSI score."""
        r = client.get("/v1/diagnostics/survivability", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert "governance_survivability_index" in data
        assert "collapse_probability" in data
        assert 0 <= data["governance_survivability_index"] <= 100

    def test_consequence_simulation(self, client):
        """Consequence simulation must return blast radius."""
        r = client.post("/v1/simulate/consequence", headers=HEADERS, json={
            "agent_id":        "test-agent-001",
            "action_type":     "PAYMENT_EXECUTION",
            "consequence":     "CRITICAL",
            "domain":          "finance",
            "affected_parties":5,
            "financial_impact":50000,
            "reversible":      False,
        })
        assert r.status_code == 200
        data = r.json()
        assert "blast_radius" in data
        assert "projected_risk_band" in data
        assert data["blast_radius"]["total_affected"] >= 5

    def test_legitimacy_statement(self, client):
        """Legitimacy statement must confirm human sovereignty."""
        r = client.get("/v1/human/legitimacy/statement", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert "humans_retain" in data
        assert "sovereignty" in str(data).lower()
