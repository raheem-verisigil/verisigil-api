from pathlib import Path
import unittest


class LegacyRegistryBridgeMigrationTests(unittest.TestCase):
    def setUp(self):
        self.sql = (
            Path(__file__).resolve().parents[1]
            / "supabase" / "migrations"
            / "20261123190000_legacy_registry_bridge.sql"
        ).read_text(encoding="utf-8").lower()

    def test_tenant_and_agent_ids_share_the_legacy_registry(self):
        self.assertIn("references public.organisations(id)", self.sql)
        self.assertIn("references public.agents(org_id, id)", self.sql)
        self.assertIn("insert into public.organisations", self.sql)
        self.assertIn("insert into public.agents", self.sql)

    def test_passport_registration_and_rotation_are_mirrored(self):
        self.assertIn("insert into public.passports", self.sql)
        self.assertIn("cryptographic_passport", self.sql)
        self.assertIn("create or replace function public.vgs_rotate_agent_identity_key", self.sql)
        self.assertIn("set status = 'revoked'", self.sql)

    def test_agent_revocation_closes_both_registry_views(self):
        self.assertIn("update public.agents", self.sql)
        self.assertIn("update public.passports", self.sql)
        self.assertIn("update public.vgs_agent_delegations", self.sql)
        self.assertIn("update public.vgs_agent_authority_commitments", self.sql)

    def test_proof_events_are_mirrored_without_raw_parameters_or_key_material(self):
        self.assertIn("insert into public.vgs_proof_events", self.sql)
        self.assertIn("'action_digest'", self.sql)
        self.assertNotIn("'parameters', new_row", self.sql)
        self.assertNotIn("'public_key_b64', new_row", self.sql)

    def test_security_definer_functions_pin_search_path(self):
        self.assertIn("set search_path = pg_catalog, public", self.sql)
        self.assertIn("alter function public.vgs_consume_validation_receipt(text, text)", self.sql)


if __name__ == "__main__":
    unittest.main()
