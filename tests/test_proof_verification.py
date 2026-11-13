import base64
import json
import unittest
from pathlib import Path

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

    def test_public_source_has_no_legacy_shared_credentials(self):
        source = Path(__file__).resolve().parents[1] / "main.py"
        text = source.read_text(encoding="utf-8")
        self.assertNotIn("vs-sandbox-demo-2026b", text)
        self.assertNotIn("vs-sandbox-demo-2026", text)
        self.assertNotIn("VrT3JN8iSKPoNkyyOanCEtfKUdvoITyXyl24FCnD+jA=", text)

    def test_legacy_route_uses_runtime_key_and_revocation_registry(self):
        source = (Path(__file__).resolve().parents[1] / "main.py").read_text(encoding="utf-8")
        route = source.split('@app.post("/v1/proof/verify"', 1)[1].split('@app.get("/v1/proof/public-key"', 1)[0]
        self.assertIn("bytes(_VERIFY_KEY)", route)
        self.assertIn("ED25519_REVOKED_KEY_IDS", route)
        self.assertNotIn("VrT3", route)


if __name__ == "__main__":
    unittest.main()
