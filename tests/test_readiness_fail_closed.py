import asyncio
import unittest
from unittest.mock import patch

import verisigil_entrypoint as entrypoint


class TestFailClosedReadiness(unittest.TestCase):
    def test_database_unavailable_returns_503(self):
        with patch.object(
            entrypoint.core.db,
            "health_check",
            return_value={"db_connected": False, "provider": "supabase", "mode": "fallback"},
        ):
            response = asyncio.run(entrypoint.hardened_readiness())

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.body and __import__("json").loads(response.body)["status"], "not_ready")

    def test_database_health_exception_returns_503(self):
        with patch.object(
            entrypoint.core.db,
            "health_check",
            side_effect=RuntimeError("database unavailable"),
        ):
            response = asyncio.run(entrypoint.hardened_readiness())

        self.assertEqual(response.status_code, 503)
        payload = __import__("json").loads(response.body)
        self.assertEqual(payload["checks"]["database"]["status"], "degraded")

    def test_healthy_database_returns_200(self):
        with patch.object(
            entrypoint.core.db,
            "health_check",
            return_value={"db_connected": True, "provider": "supabase", "mode": "persistent"},
        ):
            response = asyncio.run(entrypoint.hardened_readiness())

        self.assertEqual(response.status_code, 200)
        payload = __import__("json").loads(response.body)
        self.assertEqual(payload["status"], "ready")
        self.assertEqual(payload["checks"]["database"]["status"], "ok")


if __name__ == "__main__":
    unittest.main()
