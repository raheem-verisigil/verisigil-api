"""Regression tests for public proof verification and credential revocation.

These tests compile the production function definitions from main.py without
starting the application or connecting to Supabase.
"""
import ast
import asyncio
import base64
import copy
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from nacl.signing import SigningKey


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "main.py"


class AuthRejected(Exception):
    def __init__(self, status_code=401, detail=""):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _load_functions(*names, namespace=None):
    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
    selected = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names:
            cloned = copy.deepcopy(node)
            cloned.decorator_list = []
            selected.append(cloned)
    assert {node.name for node in selected} == set(names), "Expected production functions not found"
    module = ast.Module(body=selected, type_ignores=[])
    ast.fix_missing_locations(module)
    env = {
        "base64": base64,
        "datetime": datetime,
        "timezone": timezone,
        "Optional": Optional,
        "HTTPException": AuthRejected,
        "_check_canary": lambda value: False,
    }
    if namespace:
        env.update(namespace)
    exec(compile(module, str(SOURCE), "exec"), env)
    return env


def _signed_payload(signing_key, payload):
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "Ed25519:" + base64.b64encode(signing_key.sign(canonical).signature).decode("ascii")


def test_runtime_key_verifies_valid_payload_and_returns_same_public_key():
    key = SigningKey.generate()
    env = _load_functions(
        "verify_governance_signature",
        "proof_verify_record",
        namespace={"_VERIFY_KEY": key.verify_key},
    )
    payload = {"event": "release-approved", "sequence": 7}
    signature = _signed_payload(key, payload)
    result = asyncio.run(env["proof_verify_record"](payload, signature))
    assert result["result"] == "VERIFIED"
    assert result["public_key"] == base64.b64encode(bytes(key.verify_key)).decode("ascii")
    assert result["algorithm"] == "Ed25519"


def test_tampered_payload_is_rejected():
    key = SigningKey.generate()
    env = _load_functions(
        "verify_governance_signature",
        "proof_verify_record",
        namespace={"_VERIFY_KEY": key.verify_key},
    )
    payload = {"event": "release-approved", "sequence": 7}
    signature = _signed_payload(key, payload)
    mutated = dict(payload, sequence=8)
    result = asyncio.run(env["proof_verify_record"](mutated, signature))
    assert result["result"] == "UNVERIFIED"


def test_wrong_runtime_key_is_rejected():
    signer = SigningKey.generate()
    verifier = SigningKey.generate()
    env = _load_functions(
        "verify_governance_signature",
        "proof_verify_record",
        namespace={"_VERIFY_KEY": verifier.verify_key},
    )
    payload = {"event": "release-approved"}
    result = asyncio.run(env["proof_verify_record"](payload, _signed_payload(signer, payload)))
    assert result["result"] == "UNVERIFIED"


def test_malformed_signatures_fail_closed_and_legacy_raw_signatures_remain_supported():
    key = SigningKey.generate()
    env = _load_functions(
        "verify_governance_signature",
        "proof_verify_record",
        namespace={"_VERIFY_KEY": key.verify_key},
    )
    payload = {"event": "release-approved"}
    assert env["verify_governance_signature"](payload, "not-a-signature") is False
    assert env["verify_governance_signature"](payload, "Ed25519:%%%") is False
    assert env["verify_governance_signature"](payload, "Ed25519:" + base64.b64encode(b"x").decode()) is False
    raw_signature = base64.b64encode(key.sign(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).signature).decode("ascii")
    assert env["verify_governance_signature"](payload, raw_signature) is True


def test_verification_kit_does_not_publish_shared_auth_material():
    key = SigningKey.generate()
    env = _load_functions("verify_kit", namespace={"_VERIFY_KEY": key.verify_key})
    result = asyncio.run(env["verify_kit"]())
    assert result["public_key"] == base64.b64encode(bytes(key.verify_key)).decode("ascii")
    assert "sandbox_key" not in result
    assert "sandbox" not in result


def test_auth_accepts_only_the_operator_provisioned_api_key():
    env = _load_functions("require_api_key", namespace={"API_KEY": "operator-production-key"})
    env["require_api_key"]("operator-production-key", None)
    for rejected in (None, "", "retired-demo-token", "legacy-shared-token"):
        try:
            env["require_api_key"](rejected, None)
        except AuthRejected:
            pass
        else:
            raise AssertionError("A non-production credential was accepted")
