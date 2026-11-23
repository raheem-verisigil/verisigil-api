import base64
import json
import os
import unittest
from pathlib import Path

os.environ.setdefault("SUPABASE_URL", "https://identity-test.invalid")
os.environ.setdefault("SUPABASE_KEY", "test-anon-key-not-a-secret")
os.environ.setdefault("SUPABASE_SERVICE_KEY", "test-service-key-not-a-secret")
os.environ.setdefault("VERISIGIL_API_KEY", "test-api-key-not-a-secret")
os.environ.setdefault("SIGN_SECRET", "test-signing-secret-not-for-deployment")
os.environ.setdefault("DEPLOY_ENV", "test")

from fastapi import HTTPException
import main as core
import verisigil_entrypoint as runtime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proof_verification import public_key_id, verify_ed25519_payload


class ProofVerificationTests(unittest.TestCase):
    def setUp(self):
        self.private_key = Ed25519PrivateKey.generate()
        self.public_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.public_b64 = base64.b64encode(self.public_bytes).decode("ascii")
        self.payload = {"agent_id": "unit-test-agent", "ruling": "ALLOW", "amount": 25}
        canonical = json.dumps(self.payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.signature = "Ed25519:" + base64.b64encode(self.private_key.sign(canonical)).decode("ascii")
        self.key_id = public_key_id(self.public_b64)

    def test_valid_signature(self):
        self.assertEqual(verify_ed25519_payload(self.payload, self.signature, self.public_b64)["result"], "VERIFIED")

    def test_tampered_payload(self):
        altered = dict(self.payload, amount=25000)
        self.assertEqual(verify_ed25519_payload(altered, self.signature, self.public_b64)["result"], "UNVERIFIED")

    def test_unknown_key_id(self):
        result = verify_ed25519_payload(self.payload, self.signature, self.public_b64, key_id="not-active")
        self.assertEqual(result["message"], "Unknown verification key.")

    def test_revoked_key(self):
        result = verify_ed25519_payload(self.payload, self.signature, self.public_b64, revoked_key_ids={self.key_id})
        self.assertEqual(result["message"], "Verification key has been revoked.")

    def test_malformed_signature(self):
        self.assertEqual(verify_ed25519_payload(self.payload, "not-base64!", self.public_b64)["result"], "UNVERIFIED")

    def test_raw_base64_compatibility(self):
        raw = self.signature.removeprefix("Ed25519:")
        self.assertEqual(verify_ed25519_payload(self.payload, raw, self.public_b64)["result"], "VERIFIED")

    def test_runtime_rejects_legacy_shared_credentials(self):
        legacy_credentials = [
            base64.b64decode("dnMtc2FuZGJveC1kZW1vLTIwMjZi").decode(),
            base64.b64decode("dnMtc2FuZGJveC1kZW1vLTIwMjY=").decode(),
        ]
        for credential in legacy_credentials:
            with self.subTest(credential="legacy-sandbox-key"):
                with self.assertRaises(HTTPException):
                    core.require_api_key(credential)
        core.require_api_key(os.environ["VERISIGIL_API_KEY"])

    def test_issuer_public_key_is_derived_from_active_signing_key(self):
        expected = base64.b64encode(bytes(core._VERIFY_KEY)).decode("ascii")
        self.assertEqual(core.PUBLIC_KEY_B64, expected)

    def test_agent_identity_routes_and_auth_schemes_are_registered(self):
        schema = runtime.app.openapi()
        self.assertIn("/v1/agent-identity/agents", schema["paths"])
        self.assertIn("/v1/agent-identity/challenges", schema["paths"])
        self.assertIn("/v1/runtime/authority/evaluate", schema["paths"])
        self.assertIn("/v1/runtime/authority/consume", schema["paths"])
        schemes = schema["components"]["securitySchemes"]
        self.assertIn("SupabaseBearer", schemes)
        self.assertEqual(
            schema["paths"]["/v1/agent-identity/api-keys"]["post"]["security"],
            [{"SupabaseBearer": []}],
        )
        self.assertIn(
            {"ApiKeyAuth": []},
            schema["paths"]["/v1/runtime/authority/evaluate"]["post"]["security"],
        )

    def test_staging_entrypoint_intercepts_legacy_verify_route_with_runtime_key(self):
        source = (Path(__file__).resolve().parents[1] / "verisigil_entrypoint.py").read_text(encoding="utf-8")
        self.assertIn('request.url.path == "/v1/proof/verify"', source)
        self.assertIn("bytes(core._VERIFY_KEY)", source)
        self.assertIn("ED25519_REVOKED_KEY_IDS", source)
        self.assertIn("verify_ed25519_payload", source)


if __name__ == "__main__":
    unittest.main()
