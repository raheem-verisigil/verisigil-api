"""Security and lifecycle tests for durable validation receipt storage."""
import os
import unittest
from unittest.mock import patch

import durable_validation_receipts as durable


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class FakeAsyncClient:
    responses = []
    calls = []

    def __init__(self, *args, **kwargs):
        self.timeout = kwargs.get("timeout")

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return self.responses.pop(0)

    async def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return self.responses.pop(0)


class DurableReceiptCredentialTests(unittest.TestCase):
    def test_public_supabase_key_is_not_accepted_for_durable_storage(self):
        with patch.dict(os.environ, {
            "SUPABASE_URL": "https://project.supabase.co",
            "SUPABASE_KEY": "sb_publishable_test_only",
        }, clear=True):
            with self.assertRaises(durable.ReceiptPersistenceUnavailable):
                durable._config()

    def test_server_service_key_is_selected_not_public_key(self):
        with patch.dict(os.environ, {
            "SUPABASE_URL": "https://project.supabase.co",
            "SUPABASE_KEY": "sb_publishable_test_only",
            "SUPABASE_SERVICE_KEY": "sb_secret_test_only",
        }, clear=True):
            self.assertEqual(
                durable._config(),
                ("https://project.supabase.co", "sb_secret_test_only"),
            )

    def test_legacy_service_role_environment_name_remains_supported(self):
        with patch.dict(os.environ, {
            "SUPABASE_URL": "https://project.supabase.co",
            "SUPABASE_SERVICE_ROLE_KEY": "legacy-service-role-jwt",
        }, clear=True):
            self.assertEqual(
                durable._config(),
                ("https://project.supabase.co", "legacy-service-role-jwt"),
            )

    def test_modern_secret_key_is_not_misrepresented_as_bearer_jwt(self):
        headers = durable._headers("sb_secret_test_only")
        self.assertEqual(headers["apikey"], "sb_secret_test_only")
        self.assertNotIn("Authorization", headers)

    def test_legacy_service_role_jwt_uses_bearer_authorization(self):
        headers = durable._headers("legacy-service-role-jwt")
        self.assertEqual(headers["apikey"], "legacy-service-role-jwt")
        self.assertEqual(headers["Authorization"], "Bearer legacy-service-role-jwt")


class DurableReceiptHttpLifecycleTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        FakeAsyncClient.responses = []
        FakeAsyncClient.calls = []
        self.client_patch = patch.object(durable.httpx, "AsyncClient", FakeAsyncClient)
        self.client_patch.start()
        self.env_patch = patch.dict(os.environ, {
            "SUPABASE_URL": "https://staging-project.supabase.co",
            "SUPABASE_SERVICE_KEY": "sb_secret_test_only",
        }, clear=True)
        self.env_patch.start()

    def tearDown(self):
        self.env_patch.stop()
        self.client_patch.stop()

    async def test_persist_posts_receipt_and_record_with_minimal_return(self):
        FakeAsyncClient.responses = [FakeResponse(201)]
        await durable.persist_validation_receipt(
            "RVL-ONE", "proposal-1", {"governance_signature": "sig"},
            {"proposal_id": "proposal-1", "allowed": True, "ruling": "ALLOW"},
        )
        method, url, kwargs = FakeAsyncClient.calls[0]
        self.assertEqual(method, "POST")
        self.assertEqual(url, "https://staging-project.supabase.co/rest/v1/vgs_validation_receipts")
        self.assertEqual(kwargs["headers"]["Prefer"], "return=minimal")
        self.assertEqual(kwargs["headers"]["apikey"], "sb_secret_test_only")
        self.assertNotIn("Authorization", kwargs["headers"])
        self.assertEqual(kwargs["json"]["revalidation_id"], "RVL-ONE")
        self.assertEqual(kwargs["json"]["proposal_id"], "proposal-1")
        self.assertEqual(kwargs["json"]["record"]["ruling"], "ALLOW")

    async def test_persist_rejects_duplicate_or_database_error(self):
        FakeAsyncClient.responses = [FakeResponse(409)]
        with self.assertRaises(durable.ReceiptPersistenceUnavailable):
            await durable.persist_validation_receipt("RVL-DUP", "proposal-1", {}, {})

    async def test_load_returns_persisted_receipt_and_consumption_state(self):
        row = {
            "revalidation_id": "RVL-ONE", "proposal_id": "proposal-1",
            "receipt": {"governance_signature": "sig"},
            "record": {"proposal_id": "proposal-1", "allowed": True, "ruling": "ALLOW"},
            "consumed_at": None,
        }
        FakeAsyncClient.responses = [FakeResponse(200, [row])]
        loaded = await durable.load_validation_receipt("RVL-ONE")
        self.assertEqual(loaded, row)
        method, url, kwargs = FakeAsyncClient.calls[0]
        self.assertEqual(method, "GET")
        self.assertEqual(kwargs["params"]["revalidation_id"], "eq.RVL-ONE")
        self.assertIn("consumed_at", kwargs["params"]["select"])

    async def test_load_rejects_invalid_response_shape(self):
        FakeAsyncClient.responses = [FakeResponse(200, {"unexpected": "object"})]
        with self.assertRaises(durable.ReceiptPersistenceUnavailable):
            await durable.load_validation_receipt("RVL-ONE")

    async def test_consume_calls_atomic_rpc_with_both_identifiers(self):
        record = {"proposal_id": "proposal-1", "allowed": True, "ruling": "ALLOW"}
        FakeAsyncClient.responses = [FakeResponse(200, record)]
        consumed = await durable.consume_validation_receipt("RVL-ONE", "proposal-1")
        self.assertEqual(consumed, record)
        method, url, kwargs = FakeAsyncClient.calls[0]
        self.assertEqual(method, "POST")
        self.assertEqual(url, "https://staging-project.supabase.co/rest/v1/rpc/vgs_consume_validation_receipt")
        self.assertEqual(kwargs["json"], {
            "p_revalidation_id": "RVL-ONE", "p_proposal_id": "proposal-1",
        })

    async def test_consume_returns_none_when_receipt_was_already_consumed(self):
        FakeAsyncClient.responses = [FakeResponse(200, None)]
        self.assertIsNone(await durable.consume_validation_receipt("RVL-ONE", "proposal-1"))

    async def test_consume_fails_closed_on_rpc_error(self):
        FakeAsyncClient.responses = [FakeResponse(500, {"message": "database unavailable"})]
        with self.assertRaises(durable.ReceiptPersistenceUnavailable):
            await durable.consume_validation_receipt("RVL-ONE", "proposal-1")

    async def test_two_atomic_consume_attempts_can_have_only_one_winner(self):
        record = {"proposal_id": "proposal-1", "allowed": True, "ruling": "ALLOW"}
        FakeAsyncClient.responses = [FakeResponse(200, record), FakeResponse(200, None)]
        first = await durable.consume_validation_receipt("RVL-ONE", "proposal-1")
        second = await durable.consume_validation_receipt("RVL-ONE", "proposal-1")
        self.assertIsNotNone(first)
        self.assertIsNone(second)
        self.assertEqual(len(FakeAsyncClient.calls), 2)


if __name__ == "__main__":
    unittest.main()
