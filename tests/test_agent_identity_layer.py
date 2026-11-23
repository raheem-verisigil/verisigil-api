"""Security regression tests for the tenant-scoped agent identity layer."""
import asyncio
import base64
import os
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

os.environ.setdefault("SUPABASE_URL", "https://identity-test.invalid")
os.environ.setdefault("SUPABASE_KEY", "test-anon-key-not-a-secret")
os.environ.setdefault("SUPABASE_SERVICE_KEY", "test-service-key-not-a-secret")
os.environ.setdefault("VERISIGIL_API_KEY", "test-api-key-not-a-secret")
os.environ.setdefault("SIGN_SECRET", "test-signing-secret-not-for-deployment")
os.environ.setdefault("DEPLOY_ENV", "test")

import main as core
import agent_identity_layer as identity
from nacl.signing import SigningKey


def _future():
    return (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()


def _agent(agent_id, org_id, public_key, capabilities):
    fingerprint = identity._fingerprint(public_key)
    claims = {
        "schema": "VERISIGIL-CRYPTOGRAPHIC-PASSPORT-1.0",
        "passport_id": "passport-test",
        "agent_id": agent_id,
        "org_id": org_id,
        "issuer": "https://verisigilai.com",
        "public_key_fingerprints": [fingerprint],
        "declared_capabilities": capabilities,
        "expires_at": _future(),
    }
    return {
        "agent_id": agent_id, "org_id": org_id, "status": "ACTIVE",
        "expires_at": _future(),
        "passport": {
            "claims": claims,
            "issuer_signature": core.sign_governance_payload(claims),
        },
    }


class AgentIdentityLayerTests(unittest.TestCase):
    def setUp(self):
        self.org_id = "tenant-test"
        self.signing_key = SigningKey.generate()
        self.public_key = base64.b64encode(bytes(self.signing_key.verify_key)).decode()
        self.fingerprint = identity._fingerprint(self.public_key)

    def test_ed25519_proof_of_possession_is_bound_to_exact_payload(self):
        payload = {"agent_id": "agent-A", "action": "read_records", "parameters": {"record": "R-1"}}
        signature = base64.b64encode(self.signing_key.sign(identity._canonical(payload)).signature).decode()
        self.assertTrue(identity._verify_agent_signature(self.public_key, payload, signature))
        altered = {**payload, "parameters": {"record": "R-2"}}
        self.assertFalse(identity._verify_agent_signature(self.public_key, altered, signature))

    def test_issuer_passport_signature_detects_claim_mutation(self):
        agent = _agent("agent-A", self.org_id, self.public_key, ["read_records"])
        self.assertTrue(identity._passport_valid(agent))
        agent["passport"]["claims"]["declared_capabilities"] = ["read_records", "transfer_funds"]
        self.assertFalse(identity._passport_valid(agent))

    def test_direct_authority_requires_active_key_and_signed_capability(self):
        agent = _agent("agent-A", self.org_id, self.public_key, ["read_records"])
        key = {
            "key_id": self.fingerprint, "fingerprint": self.fingerprint,
            "public_key_b64": self.public_key, "status": "ACTIVE",
        }
        original_get_agent, original_get_key = identity._get_agent, identity._get_key

        async def fake_get_agent(org_id, agent_id):
            return agent

        async def fake_get_key(org_id, agent_id, key_id):
            return key

        identity._get_agent, identity._get_key = fake_get_agent, fake_get_key
        try:
            allowed_agent, _, reasons = asyncio.run(identity._evaluate_identity(
                self.org_id, "agent-A", self.fingerprint, "read_records", None))
            self.assertIsNotNone(allowed_agent)
            self.assertEqual(reasons, [])
            denied_agent, _, reasons = asyncio.run(identity._evaluate_identity(
                self.org_id, "agent-A", self.fingerprint, "transfer_funds", None))
            self.assertIsNone(denied_agent)
            self.assertIn("ACTION_OUTSIDE_AGENT_CAPABILITIES", reasons)
        finally:
            identity._get_agent, identity._get_key = original_get_agent, original_get_key

    def test_key_must_be_listed_in_issuer_signed_passport(self):
        agent = _agent("agent-A", self.org_id, self.public_key, ["read_records"])
        other_key = SigningKey.generate()
        other_public = base64.b64encode(bytes(other_key.verify_key)).decode()
        other_fingerprint = identity._fingerprint(other_public)
        key = {
            "key_id": other_fingerprint, "fingerprint": other_fingerprint,
            "public_key_b64": other_public, "status": "ACTIVE",
        }
        original_get_agent, original_get_key = identity._get_agent, identity._get_key

        async def fake_get_agent(org_id, agent_id):
            return agent

        async def fake_get_key(org_id, agent_id, key_id):
            return key

        identity._get_agent, identity._get_key = fake_get_agent, fake_get_key
        try:
            allowed_agent, _, reasons = asyncio.run(identity._evaluate_identity(
                self.org_id, "agent-A", other_fingerprint, "read_records", None))
            self.assertIsNone(allowed_agent)
            self.assertIn("KEY_NOT_BOUND_TO_SIGNED_PASSPORT", reasons)
        finally:
            identity._get_agent, identity._get_key = original_get_agent, original_get_key

    def test_delegated_scope_must_be_current_and_held_by_grantor(self):
        grantee = _agent("agent-B", self.org_id, self.public_key, [])
        grantor_key = SigningKey.generate()
        grantor_public = base64.b64encode(bytes(grantor_key.verify_key)).decode()
        grantor = _agent("agent-A", self.org_id, grantor_public, ["read_records"])
        grantee_key = {
            "key_id": self.fingerprint, "fingerprint": self.fingerprint,
            "public_key_b64": self.public_key, "status": "ACTIVE",
        }
        delegation = {
            "delegation_id": "delegation-1", "grantor_agent_id": "agent-A",
            "grantee_agent_id": "agent-B", "scopes": ["read_records"],
            "status": "ACTIVE", "expires_at": _future(),
        }
        original_get_agent, original_get_key, original_one = identity._get_agent, identity._get_key, identity._one

        async def fake_get_agent(org_id, agent_id):
            return {"agent-A": grantor, "agent-B": grantee}[agent_id]

        async def fake_get_key(org_id, agent_id, key_id):
            return grantee_key

        async def fake_one(table, filters):
            return delegation if table == "vgs_agent_delegations" else None

        identity._get_agent, identity._get_key, identity._one = fake_get_agent, fake_get_key, fake_one
        try:
            allowed_agent, _, reasons = asyncio.run(identity._evaluate_identity(
                self.org_id, "agent-B", self.fingerprint, "read_records", "delegation-1"))
            self.assertIsNotNone(allowed_agent)
            self.assertEqual(reasons, [])
            delegation["scopes"] = ["transfer_funds"]
            allowed_agent, _, reasons = asyncio.run(identity._evaluate_identity(
                self.org_id, "agent-B", self.fingerprint, "read_records", "delegation-1"))
            self.assertIsNone(allowed_agent)
            self.assertIn("ACTION_OUTSIDE_DELEGATION_SCOPE", reasons)
        finally:
            identity._get_agent, identity._get_key, identity._one = original_get_agent, original_get_key, original_one

    def test_challenge_is_proof_of_possession_and_one_time(self):
        challenge = {
            "challenge_id": "00000000-0000-0000-0000-000000000001",
            "org_id": self.org_id, "purpose": "REGISTER_AGENT",
            "agent_id": None, "key_fingerprint": self.fingerprint,
            "nonce": "random-one-time-nonce", "expires_at": _future(),
            "consumed_at": None,
        }
        proof = base64.b64encode(
            self.signing_key.sign(identity._canonical(identity._challenge_payload(challenge))).signature
        ).decode()
        principal = identity.Principal(
            org_id=self.org_id, principal_id="owner-1", role="owner",
            scopes=identity.ROLE_SCOPES["owner"], auth_method="supabase_jwt",
        )
        original_one, original_rpc = identity._one, identity._rpc

        async def fake_one(table, filters):
            return challenge

        async def fake_rpc(name, body):
            if challenge["consumed_at"] is not None:
                return None
            challenge["consumed_at"] = datetime.now(timezone.utc).isoformat()
            return challenge

        identity._one, identity._rpc = fake_one, fake_rpc
        try:
            consumed = asyncio.run(identity._consume_challenge(
                principal, challenge["challenge_id"], "REGISTER_AGENT", None,
                self.public_key, proof))
            self.assertEqual(consumed["challenge_id"], challenge["challenge_id"])
            with self.assertRaises(Exception):
                asyncio.run(identity._consume_challenge(
                    principal, challenge["challenge_id"], "REGISTER_AGENT", None,
                    self.public_key, proof))
        finally:
            identity._one, identity._rpc = original_one, original_rpc

    def test_supabase_secret_key_is_not_sent_as_bearer_jwt(self):
        headers = identity._service_auth_headers("sb_secret_test-only")
        self.assertEqual(headers["apikey"], "sb_secret_test-only")
        self.assertNotIn("Authorization", headers)
        legacy = identity._service_auth_headers("eyJlegacy-service-role")
        self.assertEqual(legacy["Authorization"], "Bearer eyJlegacy-service-role")
        self.assertEqual(legacy["apikey"], "eyJlegacy-service-role")

    def test_agent_signature_canonicalization_uses_rfc8785(self):
        # RFC 8785 normalizes number rendering and rejects non-I-JSON values.
        self.assertEqual(identity._canonical({"z": 333333333.33333329, "a": "€"}), '{"a":"€","z":333333333.3333333}'.encode("utf-8"))

    def test_migration_scopes_agent_keys_by_tenant(self):
        migration = Path(__file__).resolve().parents[1] / "supabase" / "migrations" / "20261123160247_cryptographic_passport_identity.sql"
        source = migration.read_text(encoding="utf-8").lower()
        key_table = source.split("create table if not exists public.vgs_agent_identity_keys", 1)[1].split("create table", 1)[0]
        self.assertIn("primary key (org_id, key_id)", key_table)
        self.assertIn("foreign key (org_id, key_id)", source)
        self.assertNotIn("references public.vgs_agent_identity_keys(key_id)", source)
        self.assertIn("foreign key (org_id, agent_id)", source)
        self.assertIn("foreign key (org_id, grantor_agent_id)", source)
        self.assertIn("foreign key (org_id, grantee_agent_id)", source)
        integrity = Path(__file__).resolve().parents[1] / "supabase" / "migrations" / "20261123161005_passport_tenant_integrity.sql"
        integrity_source = integrity.read_text(encoding="utf-8").lower()
        self.assertIn("references auth.users(id)", integrity_source)
        self.assertIn("foreign key (created_by, org_id)", integrity_source)
        self.assertIn("foreign key (org_id, agent_id)", integrity_source)
        self.assertIn("foreign key (org_id, delegation_id)", integrity_source)
        onboarding = Path(__file__).resolve().parents[1] / "supabase" / "migrations" / "20261123161200_passport_tenant_onboarding.sql"
        onboarding_source = onboarding.read_text(encoding="utf-8").lower()
        self.assertIn("create table if not exists public.vgs_agent_identity_tenants", onboarding_source)
        self.assertIn("vgs_create_agent_identity_tenant", onboarding_source)
        self.assertIn("references public.vgs_agent_identity_tenants(org_id)", onboarding_source)
        self.assertIn("grant execute on function public.vgs_create_agent_identity_tenant(uuid,uuid,text)", onboarding_source)
        self.assertEqual(source.count("security definer set search_path = pg_catalog, public"), 5)
        consume_fn = source.split("create or replace function public.vgs_consume_agent_authority_commitment", 1)[1]
        self.assertIn("consumption_receipt = p_consumption_receipt", consume_fn)
        self.assertIn("consumed_at = p_consumed_at", consume_fn)

    def test_database_consume_function_is_single_use_and_rechecks_live_authority(self):
        migration = Path(__file__).resolve().parents[1] / "supabase" / "migrations" / "20261123160247_cryptographic_passport_identity.sql"
        source = migration.read_text(encoding="utf-8").lower()
        function = source.split("create or replace function public.vgs_consume_agent_authority_commitment", 1)[1]
        self.assertIn("c.consumed_at is not null", function)
        self.assertIn("consumption_receipt = p_consumption_receipt", function)
        self.assertIn("c.expires_at <= clock_timestamp()", function)
        self.assertIn("k.status <> 'active'", function)
        self.assertIn("a.status <> 'active'", function)
        self.assertIn("d.status <> 'active'", function)
        self.assertIn("c.action_digest <> p_action_digest", function)
        self.assertIn("for update", function)
        self.assertIn("c.consumed_at is not null", function)


if __name__ == "__main__":
    unittest.main()
