from pathlib import Path
import unittest

class LegacyRlsInitPlanTests(unittest.TestCase):
    def test_all_legacy_service_role_policies_use_initplan_safe_auth_role(self):
        sql = (
            Path(__file__).resolve().parents[1]
            / "supabase" / "migrations"
            / "20261123192000_legacy_rls_initplan_optimization.sql"
        ).read_text(encoding="utf-8").lower()
        self.assertEqual(sql.count("using ((select auth.role()) = 'service_role'::text)"), 13)
        self.assertNotIn("using (auth.role()", sql)

if __name__ == "__main__":
    unittest.main()
