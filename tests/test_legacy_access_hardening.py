from pathlib import Path
import unittest


class LegacyAccessHardeningTests(unittest.TestCase):
    def setUp(self):
        self.sql = (
            Path(__file__).resolve().parents[1]
            / "supabase" / "migrations"
            / "20261123191500_legacy_access_hardening.sql"
        ).read_text(encoding="utf-8").lower()

    def test_sensitive_public_policies_are_removed(self):
        for policy in (
            '"public can read approvals"',
            '"public can read scan reports"',
            'audit_log_public_read',
            'verifiers_public_read',
            'verifiers_service_insert',
            'verifiers_service_update',
            'allow_insert_service_role',
            'service_role_all',
            'allow_all_insert',
        ):
            self.assertIn(f"drop policy if exists {policy}", self.sql)

    def test_legacy_functions_pin_search_path(self):
        self.assertIn("alter function public.vcb_prevent_mandate_reinstate()", self.sql)
        self.assertIn("alter function public.consume_sigilmark(text, text)", self.sql)
        self.assertIn("alter function public.vcb_prevent_unconsume()", self.sql)
        self.assertEqual(self.sql.count("set search_path = pg_catalog, public"), 3)

    def test_missing_foreign_key_indexes_are_added(self):
        for index in (
            "evidence_bundles_agent_id_idx",
            "evidence_bundles_org_id_idx",
            "governance_events_org_id_idx",
            "passports_agent_id_idx",
            "vcb_ledger_sigilmark_id_idx",
            "vgs_authority_records_principal_id_idx",
        ):
            self.assertIn(index, self.sql)


if __name__ == "__main__":
    unittest.main()
