"""Fail-closed Ed25519 verification for public VeriSigil proof records."""
from __future__ import annotations
import base64
import binascii
import hashlib
import json
from typing import Iterable, Optional
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def _decode_public_key(public_key_b64: str) -> bytes:
    raw = base64.b64decode(public_key_b64, validate=True)
    if len(raw) != 32:
        raise ValueError("Invalid Ed25519 public key length")
    return raw


def public_key_id(public_key_b64: str) -> str:
    return hashlib.sha256(_decode_public_key(public_key_b64)).hexdigest()[:16]


def verify_ed25519_payload(payload: dict, signature: str, public_key_b64: str,
                           key_id: Optional[str] = None,
                           revoked_key_ids: Iterable[str] = ()) -> dict:
    """Return a stable verification result; never disclose crypto exception details."""
    try:
        if not isinstance(payload, dict):
            return {"result": "UNVERIFIED", "message": "Payload must be a JSON object."}
        public_bytes = _decode_public_key(public_key_b64)
        active_id = hashlib.sha256(public_bytes).hexdigest()[:16]
        if key_id and key_id != active_id:
            return {"result": "UNVERIFIED", "message": "Unknown verification key."}
        if active_id in set(revoked_key_ids):
            return {"result": "UNVERIFIED", "message": "Verification key has been revoked."}
        encoded_signature = signature[8:] if signature.startswith("Ed25519:") else signature
        sig_bytes = base64.b64decode(encoded_signature, validate=True)
        if len(sig_bytes) != 64:
            return {"result": "UNVERIFIED", "message": "Malformed Ed25519 signature."}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(sig_bytes, canonical)
        return {"result": "VERIFIED", "message": "Signature valid. Payload untampered since sealing."}
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return {"result": "UNVERIFIED", "message": "Signature or verification key is invalid."}
