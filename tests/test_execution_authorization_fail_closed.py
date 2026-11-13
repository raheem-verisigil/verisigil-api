"""Regression tests for fail-closed execution authorization receipt binding."""
import os
import unittest

os.environ.setdefault("SUPABASE_URL", "http://127.0.0.1:1")
os.environ.setdefault("SUPABASE_KEY", "verisigil-test-only-not-a-credential")
os.environ.setdefault("VERISIGIL_API_KEY", "verisigil-test-api-key-only")
os.environ.setdefault("SIGN_SECRET", "verisigil-test-signing-secret-not-for-deployment")
os.environ.setdefault("DEPLOY_ENV", "test")

from fastapi.testclient import TestClient
import verisigil_entrypoint as runtime
import durable_validation_receipts as durable

client = TestClient(runtime.app)
HEADERS = {"x-api-key": os.environ["VERISIGIL_API_KEY"]}


class ExecutionAuthorizationFailClosedTests(unittest.TestCase):
    def setUp(self):
        runtime.VALIDATION_RECEIPTS.clear()
        self.store = {}
        self.original_load = durable.load_validation_receipt

        async def fake_load(revalidation_id):
            return self.store.get(revalidation_id)

        durable.load_validation_receipt = fake_load

    def tearDown(self):
        durable.load_validation_receipt = self.original_load

    def test_missing_revalidation_receipt_is_denied(self):
        response = client.post("/v1/execution/authorize", headers=HEADERS, json={
            "proposal_id": "proposal-without-receipt",
            "revalidation_id": "unknown-revalidation-id",
            "ttl_seconds": 30,
        })
        self.assertEqual(response.status_code, 403)
        body = response.json()
        self.assertFalse(body["allowed"])
        self.assertEqual(body["ruling"], "REVALIDATION_RECEIPT_MISSING")
        self.assertEqual(body["consequence_boundary"], "NO_EXECUTION_AUTHORIZATION_ISSUED")

    def test_proposal_mismatch_is_denied_before_core_authorization(self):
        self.store["known-rid"] = {
            "revalidation_id": "known-rid",
            "proposal_id": "proposal-A",
            "receipt": {"governance_signature": "not-reached-before-proposal-check"},
            "record": {
                "agent_id": "synthetic-agent",
                "action_type": "TRANSFER",
                "proposal_id": "proposal-A",
                "capacity_assertion_id": "synthetic-assertion",
                "required_capacity": 10,
                "amount": 10,
                "passport_id": "synthetic-passport",
                "ruling": "ALLOW",
                "allowed": True,
            },
            "consumed_at": None,
        }
        response = client.post("/v1/execution/authorize", headers=HEADERS, json={
            "proposal_id": "proposal-B",
            "revalidation_id": "known-rid",
            "ttl_seconds": 30,
        })
        self.assertEqual(response.status_code, 403)
        body = response.json()
        self.assertFalse(body["allowed"])
        self.assertEqual(body["ruling"], "REVALIDATION_PROPOSAL_MISMATCH")
        self.assertEqual(body["consequence_boundary"], "NO_EXECUTION_AUTHORIZATION_ISSUED")


if __name__ == "__main__":
    unittest.main()
