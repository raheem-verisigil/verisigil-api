"""Security regression tests for durable validation receipt credentials."""
import os
import unittest
from unittest.mock import patch

import durable_validation_receipts as durable


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


if __name__ == "__main__":
    unittest.main()
