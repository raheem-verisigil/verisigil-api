import asyncio
import json
import unittest
from unittest.mock import AsyncMock, patch

import verisigil_entrypoint as entrypoint


class TestFailClosedReadiness(unittest.TestCase):
    def test_database_unavailable_returns_503(self):
        with patch.object(
            entrypoint,
            "_db_request",
            new=AsyncMock(side_effect=RuntimeError("database unavailable")),
        ):
            response = asyncio.run(entrypoint.hardened_readiness())

        self.assertEqual(response.status_code, 503)
        payload = json.loads(response.body)
        self.assertEqual(payload["status"], "not_ready")
        self.assertEqual(payload["checks"]["database"]["status"], "degraded")

    def test_production_legacy_surface_is_denied_by_default(self):
        self.assertFalse(entrypoint._production_surface_allows("/v1/execution/control", "production", False))
        self.assertFalse(entrypoint._production_surface_allows("/v1/execution/control", "prod", False))
        self.assertTrue(entrypoint._production_surface_allows("/v1/agent-identity/agents", "production", False))
        self.assertTrue(entrypoint._production_surface_allows("/v1/runtime/authority/evaluate", "production", False))
        self.assertTrue(entrypoint._production_surface_allows("/v1/execution/control", "staging", False))
        self.assertTrue(entrypoint._production_surface_allows("/v1/execution/control", "production", True))

    def test_healthy_passport_database_returns_200(self):
        with patch.object(
            entrypoint,
            "_db_request",
            new=AsyncMock(return_value=[]),
        ):
            response = asyncio.run(entrypoint.hardened_readiness())

        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.body)
        self.assertEqual(payload["status"], "ready")
        self.assertEqual(payload["checks"]["database"]["status"], "ok")
        self.assertEqual(
            payload["checks"]["database"]["tables_checked"],
            ["vgs_agent_identities", "vgs_validation_receipts"],
        )


if __name__ == "__main__":
    unittest.main()
