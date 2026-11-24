"""Regression checks for legacy Supabase RLS hardening migration."""
import unittest
from pathlib import Path


class LegacyRlsHardeningMigrationTests(unittest.TestCase):
    def test_migration_revokes_broad_client_grants_and_adds_explicit_deny(self):
        path = (Path(__file__).resolve().parents[1] / "supabase" / "migrations" /
                "20261123183000_explicit_deny_legacy_client_roles.sql")
        sql = path.read_text(encoding="utf-8").lower()
        self.assertIn("relrowsecurity", sql)
        self.assertIn("not exists", sql)
        self.assertIn("revoke all privileges on table", sql)
        self.assertIn("from anon, authenticated", sql)
        self.assertIn("create policy", sql)
        self.assertIn("for all to anon, authenticated", sql)
        self.assertIn("using (false) with check (false)", sql)
        self.assertIn("service_role and database owners are deliberately untouched", sql)


if __name__ == "__main__":
    unittest.main()
