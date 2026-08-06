#!/usr/bin/env python3
"""
VeriSigil Public Endpoint Test Suite
=====================================
Runs automatically on every deploy.
If any public endpoint fails, deployment is flagged.

Usage:
    python3 test_public_endpoints.py
    python3 test_public_endpoints.py --base-url https://verisigil-api-production.up.railway.app
    python3 test_public_endpoints.py --fail-fast

Exit codes:
    0 — all tests passed
    1 — one or more tests failed

Expert recommendation: "Every deployment should automatically run
public endpoint health checks, conformance vectors, bypass tests,
AO replay tests, state verification tests, concurrency tests,
and documentation endpoint tests."
"""

import sys
import json
import time
import argparse
import hashlib
import threading
import urllib.request
import urllib.error
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional

# ── CONFIG ────────────────────────────────────────────────────

BASE_URL   = "https://verisigil-api-production.up.railway.app"
SANDBOX_KEY= "vs-sandbox-demo-2026b"

# ── HELPERS ───────────────────────────────────────────────────

@dataclass
class TestResult:
    name:     str
    passed:   bool
    status:   int  = 0
    details:  str  = ""
    elapsed:  float= 0.0

def _request(method: str, path: str, body: Optional[dict] = None,
             auth: bool = True, base_url: str = BASE_URL) -> tuple:
    url     = base_url + path
    headers = {"Content-Type": "application/json"}
    if auth:
        headers["x-api-key"] = SANDBOX_KEY
    data = json.dumps(body).encode() if body is not None else None
    req  = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        t0   = time.time()
        resp = urllib.request.urlopen(req, timeout=15)
        elapsed = time.time() - t0
        return resp.status, json.loads(resp.read()), elapsed
    except urllib.error.HTTPError as e:
        try:
            body_text = json.loads(e.read())
        except Exception:
            body_text = {}
        return e.code, body_text, 0.0
    except Exception as e:
        return 0, {"error": str(e)}, 0.0

def GET(path, auth=False, base_url=BASE_URL):
    return _request("GET", path, auth=auth, base_url=base_url)

def POST(path, body=None, auth=True, base_url=BASE_URL):
    return _request("POST", path, body=body or {}, auth=auth, base_url=base_url)

# ── TEST RUNNER ───────────────────────────────────────────────

class TestSuite:
    def __init__(self, base_url: str, fail_fast: bool = False):
        self.base_url  = base_url
        self.fail_fast = fail_fast
        self.results   = []
        self._ao_id    = ""
        self._nonce    = ""
        self._pipeline_id = ""
        self._commitment_id = ""

    def run(self, name: str, fn) -> TestResult:
        t0 = time.time()
        try:
            passed, details = fn()
        except Exception as e:
            passed, details = False, f"Exception: {e}"
        elapsed = time.time() - t0
        result  = TestResult(name=name, passed=passed, details=details, elapsed=elapsed)
        self.results.append(result)
        icon = "✅" if passed else "❌"
        print(f"  {icon} {name:<55} {elapsed*1000:.0f}ms")
        if not passed:
            print(f"     → {details}")
        if self.fail_fast and not passed:
            raise SystemExit(1)
        return result

    # ── SECTION 1: PUBLIC ENDPOINTS (no auth) ─────────────────

    def test_verify_kit(self):
        s, d, _ = GET("/v1/verify/kit", auth=False, base_url=self.base_url)
        if s != 200:
            return False, f"Expected 200 got {s}"
        if "verification_table" not in d:
            return False, "Missing verification_table"
        rows = d.get("verification_table", {})
        if len(rows) < 5:
            return False, f"Expected ≥5 rows, got {len(rows)}"
        return True, f"{len(rows)} verification rows present"

    def test_verify_conformance(self):
        s, d, _ = GET("/v1/verify/conformance", auth=False, base_url=self.base_url)
        if s != 200:
            return False, f"Expected 200 got {s}"
        vectors = d.get("vectors", [])
        if len(vectors) < 6:
            return False, f"Expected ≥6 vectors, got {len(vectors)}"
        return True, f"{len(vectors)} conformance vectors present"

    def test_platform_limits(self):
        s, d, _ = GET("/v1/platform/limits", auth=False, base_url=self.base_url)
        if s != 200:
            return False, f"Expected 200 got {s}"
        return True, "Platform limits accessible"

    def test_verified_boundary(self):
        s, d, _ = GET("/v1/verified-boundary", auth=False, base_url=self.base_url)
        if s != 200:
            return False, f"Expected 200 got {s}"
        for section in ["VERIFIED", "NOT_VERIFIED", "PENDING"]:
            if section not in d:
                return False, f"Missing section: {section}"
        return True, "All three boundary sections present"

    def test_signing_diagnostic(self):
        s, d, _ = GET("/v1/proof/signing-diagnostic", auth=False, base_url=self.base_url)
        if s != 200:
            return False, f"Expected 200 got {s}"
        pk = d.get("public_key","")
        if pk != "lJWG0Wabt6uATPu5Upo6UEHWGXQqMyi6LMKQC0xwpY8=":
            return False, f"Public key mismatch: {pk[:20]}..."
        if not d.get("self_verified_server_side"):
            return False, "self_verified_server_side is not true"
        return True, f"Signing key stable: {pk[:20]}..."

    def test_standing_formula(self):
        s, d, _ = GET("/v1/standing/formula", auth=False, base_url=self.base_url)
        if s != 200:
            return False, f"Expected 200 got {s}"
        preconds = d.get("preconditions", {})
        if len(preconds) < 6:
            return False, f"Expected 6 preconditions, got {len(preconds)}"
        total_weight = sum(v.get("weight", 0) for v in preconds.values())
        if abs(total_weight - 1.0) > 0.01:
            return False, f"Weights don't sum to 1.0: {total_weight}"
        return True, f"6 preconditions, weights sum to {total_weight}"

    def test_reputation_formula(self):
        s, d, _ = GET("/v1/reputation/formula", auth=False, base_url=self.base_url)
        if s != 200:
            return False, f"Expected 200 got {s}"
        if "components" not in d:
            return False, "Missing components"
        return True, "Reputation formula accessible"

    def test_convergence_weights(self):
        s, d, _ = GET("/v1/convergence/weights", auth=False, base_url=self.base_url)
        if s != 200:
            return False, f"Expected 200 got {s}"
        if "weights" not in d:
            return False, "Missing weights"
        return True, f"{len(d.get('weights', {}))} evidence source weights"

    def test_evidence_default_constitution(self):
        s, d, _ = GET("/v1/evidence/default-constitution", auth=False, base_url=self.base_url)
        if s != 200:
            return False, f"Expected 200 got {s}"
        if "accepted_evidence_types" not in d:
            return False, "Missing accepted_evidence_types"
        return True, f"{len(d.get('accepted_evidence_types', []))} accepted types"

    def test_omnix_witness_status(self):
        s, d, _ = GET("/v1/omnix/witness/status", auth=False, base_url=self.base_url)
        if s != 200:
            return False, f"Expected 200 got {s}"
        if not d.get("keypair", {}).get("public_key_b64"):
            return False, "Missing OMNIX witness public key"
        return True, f"OMNIX witness active: {d.get('operational', {}).get('active')}"

    def test_omnix_public_key(self):
        s, d, _ = GET("/v1/omnix/witness/public-key", auth=False, base_url=self.base_url)
        if s != 200:
            return False, f"Expected 200 got {s}"
        if d.get("algorithm") != "ML-DSA-65":
            return False, f"Wrong algorithm: {d.get('algorithm')}"
        return True, "ML-DSA-65 public key present"

    def test_audit_changelog(self):
        s, d, _ = GET("/v1/audit/changelog", auth=False, base_url=self.base_url)
        if s != 200:
            return False, f"Expected 200 got {s}"
        entries = d.get("entries", [])
        if len(entries) < 5:
            return False, f"Expected ≥5 changelog entries, got {len(entries)}"
        return True, f"{len(entries)} changelog entries"

    def test_vges_benchmark(self):
        s, d, _ = GET("/v1/benchmark/vges", auth=False, base_url=self.base_url)
        if s != 200:
            return False, f"Expected 200 got {s}"
        props = d.get("benchmark_properties", {})
        if len(props) < 8:
            return False, f"Expected 8 properties, got {len(props)}"
        return True, f"{len(props)} benchmark properties"

    # ── SECTION 2: BYPASS TESTS ────────────────────────────────

    def test_bypass_test(self):
        s, d, _ = POST("/v1/verify/bypass-test", {}, auth=True, base_url=self.base_url)
        if s != 200:
            return False, f"Expected 200 got {s} — {d}"
        if not d.get("all_bypasses_rejected"):
            return False, "all_bypasses_rejected is not true"
        if not d.get("custody_claim_holds"):
            return False, "custody_claim_holds is not true"
        nonce_count = d.get("test_results",{}).get("replayed_nonce",{}).get("nonce_ledger_count", -1)
        return True, f"All bypasses rejected. Nonce ledger count: {nonce_count}"

    # ── SECTION 3: AO FLOW ─────────────────────────────────────

    def test_intercept(self):
        s, d, _ = POST("/v1/intercept", {
            "agent_id": "test-suite-agent",
            "action_type": "read_report",
            "consequence": "ADVISORY",
            "authority_scope": ["data.read"],
            "human_present": False,
            "irreversible": False
        }, base_url=self.base_url)
        if s != 200:
            return False, f"Expected 200 got {s}"
        if "ruling" not in d:
            return False, "No ruling in response"
        if not d.get("governance_signature","").startswith("Ed25519:"):
            return False, "Governance signature missing or malformed"
        if d.get("ruling") != "ALLOW":
            return False, f"Expected ALLOW for ADVISORY, got {d.get('ruling')}"
        return True, f"ruling={d['ruling']} | intercept_id={d.get('intercept_id','')}"

    def test_ao_issue(self):
        # First get an intercept_id
        s, d, _ = POST("/v1/intercept", {
            "agent_id": "test-suite-agent",
            "action_type": "read_report",
            "consequence": "ADVISORY",
            "authority_scope": ["data.read"]
        }, base_url=self.base_url)
        if s != 200:
            return False, f"Intercept failed: {s}"
        intercept_id = d.get("intercept_id","")

        s, d, _ = POST("/v1/ao/issue", {
            "agent_id": "test-suite-agent",
            "action_type": "read_report",
            "consequence": "ADVISORY",
            "intercept_id": intercept_id
        }, base_url=self.base_url)
        if s != 200:
            return False, f"Expected 200 got {s}"
        if "ao_id" not in d or "nonce" not in d:
            return False, "Missing ao_id or nonce"
        self._ao_id = d["ao_id"]
        self._nonce = d["nonce"]
        return True, f"ao_id={self._ao_id} | ttl={d.get('ttl_seconds')}s"

    def test_ao_verify_first(self):
        if not self._ao_id:
            return False, "No ao_id from previous test"
        s, d, _ = POST("/v1/ao/verify", {
            "ao_id":       self._ao_id,
            "nonce":       self._nonce,
            "agent_id":    "test-suite-agent",
            "action_type": "read_report"
        }, base_url=self.base_url)
        if s != 200:
            return False, f"Expected 200 got {s}"
        if d.get("result") != "VALID_AND_UNCONSUMED":
            return False, f"Expected VALID_AND_UNCONSUMED, got {d.get('result')}"
        if not d.get("single_use_enforced"):
            return False, "single_use_enforced not true"
        return True, f"result={d['result']} | consumed_at={d.get('consumed_at','')[:19]}"

    def test_ao_verify_replay(self):
        if not self._ao_id:
            return False, "No ao_id from previous test"
        s, d, _ = POST("/v1/ao/verify", {
            "ao_id":       self._ao_id,
            "nonce":       self._nonce,
            "agent_id":    "test-suite-agent",
            "action_type": "read_report"
        }, base_url=self.base_url)
        if s != 200:
            return False, f"Expected 200 got {s}"
        if d.get("result") != "ALREADY_CONSUMED":
            return False, f"Replay not blocked — got {d.get('result')}"
        return True, f"Replay correctly blocked: {d['result']}"

    def test_ao_verify_fabricated(self):
        s, d, _ = POST("/v1/ao/verify", {
            "ao_id": "AO-FABRICATED-TESTSUITE-000",
            "nonce": "fakefakefakefake",
            "agent_id": "test-suite-agent"
        }, base_url=self.base_url)
        if s != 200:
            return False, f"Expected 200 got {s}"
        if d.get("result") != "NOT_FOUND":
            return False, f"Expected NOT_FOUND, got {d.get('result')}"
        return True, f"Fabricated AO correctly rejected: {d['result']}"

    # ── SECTION 4: CV-003 GOVERNANCE RULING ───────────────────

    def test_cv003_escalate(self):
        """HIGH + irreversible + human_present=True must return ESCALATE"""
        s, d, _ = POST("/v1/intercept", {
            "agent_id":      "test-suite-agent",
            "action_type":   "transfer_funds",
            "consequence":   "HIGH",
            "human_present": True,
            "authority_scope": ["finance.transfer"],
            "irreversible":  True
        }, base_url=self.base_url)
        if s != 200:
            return False, f"Expected 200 got {s}"
        if d.get("ruling") != "ESCALATE":
            return False, f"CV-003: Expected ESCALATE, got {d.get('ruling')}"
        signals = {sig.get("signal"): sig for sig in d.get("signals", [])}
        hie = signals.get("HIGH_IRREVERSIBLE_ESCALATE", {})
        if not hie.get("escalate"):
            return False, "HIGH_IRREVERSIBLE_ESCALATE signal not set"
        return True, f"CV-003 PASS: ruling=ESCALATE, HIGH_IRREVERSIBLE_ESCALATE=true"

    def test_cv003_deny_control(self):
        """HIGH + irreversible + human_present=False must return DENY"""
        s, d, _ = POST("/v1/intercept", {
            "agent_id":      "test-suite-agent",
            "action_type":   "transfer_funds",
            "consequence":   "HIGH",
            "human_present": False,
            "authority_scope": ["finance.transfer"],
            "irreversible":  True
        }, base_url=self.base_url)
        if s != 200:
            return False, f"Expected 200 got {s}"
        if d.get("ruling") != "DENY":
            return False, f"CV-003 control: Expected DENY, got {d.get('ruling')}"
        return True, f"CV-003 control PASS: ruling=DENY"

    # ── SECTION 5: CV-005 STATE FRESHNESS ─────────────────────

    def test_cv005_commit(self):
        s, d, _ = POST("/v1/state/commit", {
            "agent_id":    "test-suite-agent",
            "state_fields": {"balance": 500, "role": "user"},
            "ttl_seconds": 300
        }, base_url=self.base_url)
        if s != 200:
            return False, f"Expected 200 got {s}"
        state_hash = d.get("state_hash","")
        if state_hash == "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a":
            return False, "CV-005 BUG STILL PRESENT — state_hash is empty JSON hash"
        self._commitment_id = d.get("commitment_id","")
        return True, f"state_hash={state_hash[:16]}... (not empty JSON hash)"

    def test_cv005_unchanged(self):
        """Unchanged state must return FRESH"""
        if not self._commitment_id:
            return False, "No commitment_id from previous test"
        s, d, _ = POST("/v1/state/verify", {
            "commitment_id": self._commitment_id,
            "state_fields":  {"balance": 500, "role": "user"}
        }, base_url=self.base_url)
        if s != 200:
            return False, f"Expected 200 got {s}"
        if d.get("result") != "FRESH":
            return False, f"Expected FRESH, got {d.get('result')} — CV-005 may still be broken"
        return True, f"result=FRESH ✓ (unchanged state correctly recognised)"

    def test_cv005_changed(self):
        """Changed state must return STATE_CHANGED"""
        if not self._commitment_id:
            return False, "No commitment_id from previous test"
        s, d, _ = POST("/v1/state/verify", {
            "commitment_id": self._commitment_id,
            "state_fields":  {"balance": 0, "role": "admin"}
        }, base_url=self.base_url)
        if s != 200:
            return False, f"Expected 200 got {s}"
        if d.get("result") != "STATE_CHANGED":
            return False, f"Expected STATE_CHANGED, got {d.get('result')}"
        return True, f"result=STATE_CHANGED ✓ (state change correctly detected)"

    # ── SECTION 6: PAYLOAD CONTINUITY ─────────────────────────

    def test_continuity_seal(self):
        s, d, _ = POST("/v1/continuity/payload", {
            "payload": {"amount": 100, "account": "TEST-SUITE"}
        }, base_url=self.base_url)
        if s != 200:
            return False, f"Expected 200 got {s}"
        if "payload_hash" not in d:
            return False, "Missing payload_hash"
        self._pipeline_id = d.get("pipeline_id","")
        return True, f"pipeline_id={self._pipeline_id} | hash={d['payload_hash'][:16]}..."

    def test_continuity_unmodified(self):
        if not self._pipeline_id:
            return False, "No pipeline_id from previous test"
        s, d, _ = POST("/v1/continuity/hop", {
            "pipeline_id": self._pipeline_id,
            "system_id":   "test-suite-hop-1",
            "payload":     {"amount": 100, "account": "TEST-SUITE"}
        }, base_url=self.base_url)
        if s != 200:
            return False, f"Expected 200 got {s}"
        if "CONTINUE" not in d.get("ruling",""):
            return False, f"Expected CONTINUE ruling, got: {d.get('ruling','')}"
        return True, f"Unmodified payload → CONTINUE ✓"

    def test_continuity_tampered(self):
        if not self._pipeline_id:
            return False, "No pipeline_id from previous test"
        s, d, _ = POST("/v1/continuity/hop", {
            "pipeline_id": self._pipeline_id,
            "system_id":   "test-suite-hop-2",
            "payload":     {"amount": 999999, "account": "EVIL"}
        }, base_url=self.base_url)
        if s != 200:
            return False, f"Expected 200 got {s}"
        if "HALT" not in d.get("ruling",""):
            return False, f"Tamper not detected — got: {d.get('ruling','')}"
        return True, f"Tampered payload → HALT ✓"

    # ── SECTION 7: CONCURRENCY TEST ────────────────────────────

    def test_concurrency_replay(self):
        """
        Issue one AO. Launch 5 concurrent verify calls.
        Exactly one must return VALID_AND_UNCONSUMED.
        All others must return ALREADY_CONSUMED.
        This is Alkama's Run 3b concurrency test.
        """
        # Get fresh intercept + AO
        s, d, _ = POST("/v1/intercept", {
            "agent_id": "test-suite-concurrent",
            "action_type": "concurrent_test",
            "consequence": "ADVISORY",
            "authority_scope": ["data.read"]
        }, base_url=self.base_url)
        if s != 200:
            return False, f"Intercept failed: {s}"

        s, d, _ = POST("/v1/ao/issue", {
            "agent_id":    "test-suite-concurrent",
            "action_type": "concurrent_test",
            "consequence": "ADVISORY",
            "intercept_id": d.get("intercept_id","")
        }, base_url=self.base_url)
        if s != 200:
            return False, f"AO issue failed: {s}"

        ao_id = d.get("ao_id","")
        nonce = d.get("nonce","")
        results = []
        lock    = threading.Lock()

        def verify_once():
            _, resp, _ = POST("/v1/ao/verify", {
                "ao_id": ao_id, "nonce": nonce,
                "agent_id": "test-suite-concurrent",
                "action_type": "concurrent_test"
            }, base_url=self.base_url)
            with lock:
                results.append(resp.get("result",""))

        threads = [threading.Thread(target=verify_once) for _ in range(5)]
        for t in threads: t.start()
        for t in threads: t.join()

        proceeds  = results.count("VALID_AND_UNCONSUMED")
        consumed  = results.count("ALREADY_CONSUMED")

        if proceeds != 1:
            return False, f"Expected exactly 1 PROCEED, got {proceeds}. Results: {results}"
        if consumed != 4:
            return False, f"Expected 4 ALREADY_CONSUMED, got {consumed}. Results: {results}"
        return True, f"Concurrency: 1 PROCEED + {consumed} ALREADY_CONSUMED ✓ (SQLite UNIQUE holds)"

    def run_all(self):
        b = self.base_url
        print(f"\n{'='*65}")
        print(f"VeriSigil Public Endpoint Test Suite")
        print(f"Base URL: {b}")
        print(f"Time:     {datetime.now(timezone.utc).isoformat()}")
        print(f"{'='*65}\n")

        sections = [
            ("SECTION 1 — Public Endpoints (no auth)", [
                ("GET /v1/verify/kit",                   self.test_verify_kit),
                ("GET /v1/verify/conformance",           self.test_verify_conformance),
                ("GET /v1/platform/limits",              self.test_platform_limits),
                ("GET /v1/verified-boundary",            self.test_verified_boundary),
                ("GET /v1/proof/signing-diagnostic",     self.test_signing_diagnostic),
                ("GET /v1/standing/formula",             self.test_standing_formula),
                ("GET /v1/reputation/formula",           self.test_reputation_formula),
                ("GET /v1/convergence/weights",          self.test_convergence_weights),
                ("GET /v1/evidence/default-constitution",self.test_evidence_default_constitution),
                ("GET /v1/omnix/witness/status",         self.test_omnix_witness_status),
                ("GET /v1/omnix/witness/public-key",     self.test_omnix_public_key),
                ("GET /v1/audit/changelog",              self.test_audit_changelog),
                ("GET /v1/benchmark/vges",               self.test_vges_benchmark),
            ]),
            ("SECTION 2 — Bypass Tests", [
                ("POST /v1/verify/bypass-test",          self.test_bypass_test),
            ]),
            ("SECTION 3 — AO Flow", [
                ("POST /v1/intercept",                   self.test_intercept),
                ("POST /v1/ao/issue",                    self.test_ao_issue),
                ("POST /v1/ao/verify (first — consume)", self.test_ao_verify_first),
                ("POST /v1/ao/verify (replay — HALT)",   self.test_ao_verify_replay),
                ("POST /v1/ao/verify (fabricated — NOT_FOUND)", self.test_ao_verify_fabricated),
            ]),
            ("SECTION 4 — CV-003 Governance Ruling", [
                ("CV-003: HIGH+irrev+human → ESCALATE",  self.test_cv003_escalate),
                ("CV-003: HIGH+irrev+no_human → DENY",   self.test_cv003_deny_control),
            ]),
            ("SECTION 5 — CV-005 State Freshness", [
                ("POST /v1/state/commit",                self.test_cv005_commit),
                ("POST /v1/state/verify (unchanged→FRESH)",   self.test_cv005_unchanged),
                ("POST /v1/state/verify (changed→STATE_CHANGED)", self.test_cv005_changed),
            ]),
            ("SECTION 6 — Payload Continuity", [
                ("POST /v1/continuity/payload (seal)",   self.test_continuity_seal),
                ("POST /v1/continuity/hop (unmodified → CONTINUE)", self.test_continuity_unmodified),
                ("POST /v1/continuity/hop (tampered → HALT)", self.test_continuity_tampered),
            ]),
            ("SECTION 7 — Concurrency (SQLite UNIQUE)", [
                ("5× concurrent AO verify → 1 PROCEED + 4 HALT", self.test_concurrency_replay),
            ]),
        ]

        for section_name, tests in sections:
            print(f"\n{section_name}")
            print(f"{'─'*65}")
            for test_name, test_fn in tests:
                self.run(test_name, test_fn)

        # ── SUMMARY ───────────────────────────────────────────
        passed  = sum(1 for r in self.results if r.passed)
        failed  = sum(1 for r in self.results if not r.passed)
        total   = len(self.results)
        elapsed = sum(r.elapsed for r in self.results)

        print(f"\n{'='*65}")
        print(f"RESULT: {passed}/{total} passed  |  {failed} failed  |  {elapsed*1000:.0f}ms total")
        print(f"{'='*65}")

        if failed > 0:
            print(f"\nFAILED TESTS:")
            for r in self.results:
                if not r.passed:
                    print(f"  ❌ {r.name}")
                    print(f"     {r.details}")
            print()

        if failed == 0:
            print("\n✅ ALL TESTS PASSED — safe to deploy\n")
        else:
            print(f"\n❌ {failed} TEST(S) FAILED — do not publish until fixed\n")

        return failed == 0


# ── ENTRY POINT ───────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VeriSigil Public Endpoint Test Suite")
    parser.add_argument("--base-url", default=BASE_URL, help="API base URL")
    parser.add_argument("--fail-fast", action="store_true", help="Stop on first failure")
    args = parser.parse_args()

    suite  = TestSuite(base_url=args.base_url, fail_fast=args.fail_fast)
    passed = suite.run_all()
    sys.exit(0 if passed else 1)
