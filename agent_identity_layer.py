"""Tenant-scoped Cryptographic Passport and runtime-authority API.

This module is deliberately separate from the legacy passport routes. It uses
verified Supabase Auth identities or tenant API keys, durable Postgres records,
proof-of-possession for Ed25519 keys, and an atomic database consume operation.
It never accepts an agent private key.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

import httpx
import nacl.exceptions
import rfc8785
from nacl.signing import VerifyKey
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

import main as core

router = APIRouter(tags=["Cryptographic Passport & Runtime Authority"])

KNOWN_SCOPES = {
    "agents:read", "agents:write", "agents:revoke", "keys:write",
    "delegations:write", "authority:evaluate", "authority:consume",
    "receipts:read", "api_keys:write",
}
ROLE_SCOPES = {
    "owner": sorted(KNOWN_SCOPES),
    "admin": sorted(KNOWN_SCOPES - {"api_keys:write"}),
    "operator": ["agents:read", "authority:evaluate", "authority:consume", "receipts:read"],
    "auditor": ["agents:read", "receipts:read"],
}
ACTION_RE = re.compile(r"^[a-z][a-z0-9_.:-]{1,79}$")
MAX_PARAMETERS_BYTES = 65536


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _require_uuid(value: str, field: str) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise HTTPException(422, f"{field} must be a UUID.") from exc


def _iso(value: datetime | None = None) -> str:
    return (value or _now()).isoformat()


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _canonical(value: Any) -> bytes:
    """RFC 8785 JSON Canonicalization Scheme for agent-signed payloads."""
    return rfc8785.dumps(value)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _decode_public_key(value: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise HTTPException(422, "public_key must be valid Base64 Ed25519 public-key bytes.") from exc
    if len(raw) != 32:
        raise HTTPException(422, "Ed25519 public keys must contain exactly 32 bytes.")
    return raw


def _fingerprint(public_key: str) -> str:
    return hashlib.sha256(_decode_public_key(public_key)).hexdigest()


def _verify_agent_signature(public_key: str, payload: dict, signature: str) -> bool:
    try:
        encoded = signature[8:] if signature.startswith("Ed25519:") else signature
        raw_signature = base64.b64decode(encoded, validate=True)
        if len(raw_signature) != 64:
            return False
        VerifyKey(_decode_public_key(public_key)).verify(_canonical(payload), raw_signature)
        return True
    except (ValueError, TypeError, binascii.Error, nacl.exceptions.BadSignatureError):
        return False


def _service_auth_headers(key: str, prefer: str = "return=representation") -> dict[str, str]:
    """Build server-only Supabase headers for legacy JWT or modern secret key."""
    headers = {
        "apikey": key,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Prefer": prefer,
    }
    # Modern Supabase secret API keys are opaque and must be sent via apikey
    # only. Legacy service_role JWTs may also be sent as Bearer credentials.
    if not key.startswith("sb_secret_"):
        headers["Authorization"] = f"Bearer {key}"
    return headers


async def _db_request(method: str, path: str, *, params: dict | None = None,
                      body: dict | None = None, prefer: str = "return=representation") -> Any:
    base = (os.environ.get("SUPABASE_URL") or "").strip().rstrip("/")
    key = (os.environ.get("SUPABASE_SERVICE_KEY") or os.environ.get("SUPABASE_SERVICE_ROLE_KEY") or "").strip()
    if not base.startswith("https://") or not key:
        raise HTTPException(503, "Identity persistence is not configured; authority fails closed.")
    headers = _service_auth_headers(key, prefer)
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.request(method, f"{base}/rest/v1/{path}",
                                            headers=headers, params=params, json=body)
        if response.status_code >= 400:
            raise HTTPException(503, "Identity persistence rejected the operation; no authority was granted.")
        if response.status_code == 204 or not response.content:
            return None
        return response.json()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(503, "Identity persistence is unavailable; authority fails closed.") from exc


async def _select(table: str, filters: dict, *, limit: int = 1) -> list[dict]:
    params = {"select": "*", "limit": str(limit)}
    params.update({key: f"eq.{value}" for key, value in filters.items()})
    result = await _db_request("GET", table, params=params)
    if not isinstance(result, list):
        raise HTTPException(503, "Identity persistence returned an invalid record set.")
    return result


async def _one(table: str, filters: dict) -> dict | None:
    rows = await _select(table, filters, limit=1)
    return rows[0] if rows else None


async def _insert(table: str, body: dict) -> dict:
    result = await _db_request("POST", table, body=body)
    if isinstance(result, list) and result:
        return result[0]
    if isinstance(result, dict):
        return result
    raise HTTPException(503, "Identity persistence did not confirm the inserted record.")


async def _patch(table: str, filters: dict, body: dict) -> dict | None:
    params = {key: f"eq.{value}" for key, value in filters.items()}
    result = await _db_request("PATCH", table, params=params, body=body)
    return result[0] if isinstance(result, list) and result else None


async def _rpc(name: str, body: dict) -> Any:
    return await _db_request("POST", f"rpc/{name}", body=body)


def _rpc_record(result: Any) -> dict | None:
    if isinstance(result, list):
        return result[0] if result and isinstance(result[0], dict) else None
    return result if isinstance(result, dict) else None


class Principal(BaseModel):
    org_id: str
    principal_id: str
    role: str
    scopes: list[str]
    auth_method: Literal["supabase_jwt", "tenant_api_key"]


async def get_verified_supabase_user(request: Request) -> dict:
    """Validate the caller's Supabase access token without requiring a tenant."""
    authorization = request.headers.get("authorization", "")
    if not authorization.startswith("Bearer ") or not authorization[7:].strip():
        raise HTTPException(401, "Supply a valid Supabase Bearer access token.")
    token = authorization[7:].strip()
    base = (os.environ.get("SUPABASE_URL") or "").strip().rstrip("/")
    anon_key = (os.environ.get("SUPABASE_ANON_KEY") or os.environ.get("SUPABASE_KEY") or "").strip()
    if not base.startswith("https://") or not anon_key:
        raise HTTPException(503, "Supabase Auth verification is not configured.")
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.get(
                f"{base}/auth/v1/user",
                headers={"apikey": anon_key, "Authorization": f"Bearer {token}"},
            )
        if response.status_code != 200:
            raise HTTPException(401, "Supabase access token is invalid or expired.")
        user = response.json()
        if not user.get("id"):
            raise HTTPException(401, "Supabase Auth returned no verified user identity.")
        return user
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(503, "Supabase Auth could not verify the user.") from exc


async def get_principal(request: Request) -> Principal:
    """Authenticate a Supabase user through Auth, or a hashed tenant API key."""
    authorization = request.headers.get("authorization", "")
    api_key = request.headers.get("x-api-key", "")
    if authorization.startswith("Bearer ") and authorization[7:].strip():
        user = await get_verified_supabase_user(request)
        user_id = str(user["id"])
        memberships = await _select("vgs_agent_identity_memberships",
                                    {"user_id": user_id, "status": "ACTIVE"}, limit=50)
        if not memberships:
            raise HTTPException(403, "No active VeriSigil tenant membership is assigned to this user.")
        requested_org = request.headers.get("x-org-id")
        if requested_org:
            matches = [item for item in memberships if str(item.get("org_id")) == requested_org]
            if len(matches) != 1:
                raise HTTPException(403, "The requested tenant is not an active membership for this user.")
            membership = matches[0]
        elif len(memberships) == 1:
            membership = memberships[0]
        else:
            raise HTTPException(400, "This user belongs to multiple tenants; supply x-org-id for an active membership.")
        tenant = await _one("vgs_agent_identity_tenants", {
            "org_id": str(membership["org_id"]), "status": "ACTIVE",
        })
        if not tenant:
            raise HTTPException(403, "The selected VeriSigil tenant is suspended or unavailable.")
        role = str(membership.get("role") or "auditor").lower()
        return Principal(org_id=str(membership["org_id"]), principal_id=user_id,
                         role=role, scopes=ROLE_SCOPES.get(role, ROLE_SCOPES["auditor"]),
                         auth_method="supabase_jwt")

    if api_key:
        key_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        row = await _one("vgs_agent_identity_api_keys", {"key_hash": key_hash, "status": "ACTIVE"})
        if not row:
            raise HTTPException(401, "Tenant API key is invalid or revoked.")
        if row.get("expires_at") and _parse_time(row["expires_at"]) <= _now():
            raise HTTPException(401, "Tenant API key has expired.")
        tenant = await _one("vgs_agent_identity_tenants", {
            "org_id": str(row["org_id"]), "status": "ACTIVE",
        })
        if not tenant:
            raise HTTPException(403, "The API key's tenant is suspended or unavailable.")
        scopes = row.get("scopes") or []
        if not isinstance(scopes, list) or any(not isinstance(scope, str) for scope in scopes) or not set(scopes).issubset(KNOWN_SCOPES):
            raise HTTPException(403, "Tenant API key has invalid scope metadata.")
        return Principal(org_id=str(row["org_id"]), principal_id=str(row["key_id"]),
                         role="api_key", scopes=scopes, auth_method="tenant_api_key")
    raise HTTPException(401, "Supply a verified Supabase Bearer token or tenant-scoped x-api-key.")


def _need(principal: Principal, scope: str) -> None:
    if scope not in principal.scopes:
        raise HTTPException(403, f"Required scope is missing: {scope}")


def _require_jwt_owner(principal: Principal) -> None:
    if principal.auth_method != "supabase_jwt" or principal.role != "owner":
        raise HTTPException(403, "Only a verified tenant owner can create tenant API keys.")


async def _get_agent(org_id: str, agent_id: str) -> dict:
    agent_id = _require_uuid(agent_id, "agent_id")
    row = await _one("vgs_agent_identities", {"org_id": org_id, "agent_id": agent_id})
    if not row:
        raise HTTPException(404, "Agent identity not found in this tenant.")
    return row


async def _get_key(org_id: str, agent_id: str, key_id: str) -> dict:
    agent_id = _require_uuid(agent_id, "agent_id")
    if not re.fullmatch(r"[0-9a-f]{64}", key_id):
        raise HTTPException(422, "key_id must be a SHA-256 Ed25519 fingerprint.")
    row = await _one("vgs_agent_identity_keys", {
        "org_id": org_id, "agent_id": agent_id, "key_id": key_id,
    })
    if not row:
        raise HTTPException(404, "Agent key not found in this tenant.")
    return row


def _agent_is_active(agent: dict) -> bool:
    try:
        return agent.get("status") == "ACTIVE" and _parse_time(agent["expires_at"]) > _now()
    except Exception:
        return False


def _passport_valid(agent: dict) -> bool:
    passport = agent.get("passport") or {}
    claims = passport.get("claims")
    signature = passport.get("issuer_signature", "")
    if not isinstance(claims, dict):
        return False
    if claims.get("agent_id") != agent.get("agent_id") or claims.get("org_id") != agent.get("org_id"):
        return False
    return bool(core.verify_governance_signature(claims, signature))


def _challenge_payload(challenge: dict) -> dict:
    return {
        "challenge_id": challenge["challenge_id"],
        "nonce": challenge["nonce"],
        "org_id": challenge["org_id"],
        "key_fingerprint": challenge["key_fingerprint"],
        "purpose": challenge["purpose"],
        "agent_id": challenge.get("agent_id"),
    }


async def _consume_challenge(principal: Principal, challenge_id: str, purpose: str,
                             agent_id: str | None, public_key: str, proof: str) -> dict:
    fingerprint = _fingerprint(public_key)
    challenge_id = _require_uuid(challenge_id, "challenge_id")
    challenge = await _one("vgs_agent_identity_challenges", {
        "challenge_id": challenge_id, "org_id": principal.org_id,
    })
    if not challenge or challenge.get("purpose") != purpose:
        raise HTTPException(403, "Identity challenge is missing or has the wrong purpose.")
    if challenge.get("agent_id") != agent_id or challenge.get("key_fingerprint") != fingerprint:
        raise HTTPException(403, "Identity challenge does not match this agent and public key.")
    if _parse_time(challenge["expires_at"]) <= _now() or challenge.get("consumed_at"):
        raise HTTPException(409, "Identity challenge has expired or was already consumed.")
    if not _verify_agent_signature(public_key, _challenge_payload(challenge), proof):
        raise HTTPException(401, "Ed25519 proof of possession is invalid.")
    consumed = _rpc_record(await _rpc("vgs_consume_agent_identity_challenge", {
        "p_challenge_id": challenge_id, "p_org_id": principal.org_id,
        "p_purpose": purpose, "p_key_fingerprint": fingerprint,
    }))
    if not consumed:
        raise HTTPException(409, "Identity challenge was already consumed or expired.")
    return challenge


def _passport(agent_id: str, org_id: str, agent_name: str, did: str,
              capabilities: list[str], key_fingerprints: list[str],
              issued_at: str, expires_at: str, version: int = 1) -> dict:
    claims = {
        "schema": "VERISIGIL-CRYPTOGRAPHIC-PASSPORT-1.0",
        "passport_id": str(uuid.uuid4()),
        "passport_version": version,
        "agent_id": agent_id,
        "did": did,
        "org_id": org_id,
        "agent_name": agent_name,
        "issuer": "https://verisigilai.com",
        "algorithm": "Ed25519",
        "public_key_fingerprints": key_fingerprints,
        "declared_capabilities": capabilities,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "status": "ACTIVE",
    }
    return {"claims": claims, "issuer_signature": core.sign_governance_payload(claims)}


def _runtime_action_payload(agent_id: str, key_id: str, action: str,
                            parameters: dict, delegation_id: str | None) -> dict:
    return {
        "agent_id": agent_id, "key_id": key_id, "action": action,
        "parameters": parameters, "delegation_id": delegation_id,
    }


async def _evaluate_identity(org_id: str, agent_id: str, key_id: str,
                             action: str, delegation_id: str | None) -> tuple[dict | None, dict, list[str]]:
    reasons: list[str] = []
    agent = await _get_agent(org_id, agent_id)
    key = await _get_key(org_id, agent_id, key_id)
    if not _agent_is_active(agent):
        reasons.append("AGENT_REVOKED_OR_EXPIRED")
    if not _passport_valid(agent):
        reasons.append("PASSPORT_SIGNATURE_INVALID")
    if key.get("status") != "ACTIVE":
        reasons.append("AGENT_KEY_REVOKED_OR_INACTIVE")
    try:
        actual_fingerprint = _fingerprint(key.get("public_key_b64", ""))
        if actual_fingerprint != key.get("fingerprint") or actual_fingerprint != key_id:
            reasons.append("AGENT_KEY_FINGERPRINT_MISMATCH")
    except HTTPException:
        reasons.append("AGENT_PUBLIC_KEY_INVALID")
    passport = agent.get("passport") or {}
    claims = passport.get("claims") or {}
    capabilities = claims.get("declared_capabilities") or []
    if key.get("fingerprint") not in (claims.get("public_key_fingerprints") or []):
        reasons.append("KEY_NOT_BOUND_TO_SIGNED_PASSPORT")
    if delegation_id:
        delegation = await _one("vgs_agent_delegations", {
            "org_id": org_id, "delegation_id": delegation_id,
            "grantee_agent_id": agent_id, "status": "ACTIVE",
        })
        if not delegation:
            reasons.append("DELEGATION_MISSING_OR_REVOKED")
        else:
            grantor = await _get_agent(org_id, str(delegation["grantor_agent_id"]))
            if not _agent_is_active(grantor) or not _passport_valid(grantor):
                reasons.append("DELEGATOR_REVOKED_OR_INVALID")
            if action not in (delegation.get("scopes") or []):
                reasons.append("ACTION_OUTSIDE_DELEGATION_SCOPE")
            grantor_caps = ((grantor.get("passport") or {}).get("claims") or {}).get("declared_capabilities") or []
            if action not in grantor_caps:
                reasons.append("DELEGATOR_DOES_NOT_HOLD_ACTION_CAPABILITY")
            try:
                if _parse_time(delegation["expires_at"]) <= _now():
                    reasons.append("DELEGATION_EXPIRED")
            except Exception:
                reasons.append("DELEGATION_EXPIRY_INVALID")
    elif action not in capabilities:
        reasons.append("ACTION_OUTSIDE_AGENT_CAPABILITIES")
    return (agent if not reasons else None), key, reasons


class TenantCreate(BaseModel):
    tenant_name: str = Field(min_length=2, max_length=120)


class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    scopes: list[str] = Field(min_length=1, max_length=8)
    expires_in_days: int = Field(default=90, ge=1, le=365)


class ChallengeCreate(BaseModel):
    purpose: Literal["REGISTER_AGENT", "ROTATE_KEY"]
    public_key: str
    agent_id: str | None = None


class AgentCreate(BaseModel):
    agent_name: str = Field(min_length=2, max_length=120)
    public_key: str
    capabilities: list[str] = Field(min_length=1, max_length=64)
    expires_in_days: int = Field(default=90, ge=1, le=365)
    challenge_id: str
    proof_of_possession: str


class KeyRotate(BaseModel):
    public_key: str
    challenge_id: str
    proof_of_possession: str
    replace_existing: bool = True


class DelegationCreate(BaseModel):
    grantor_agent_id: str
    grantee_agent_id: str
    scopes: list[str] = Field(min_length=1, max_length=64)
    expires_at: str


class AuthorityEvaluate(BaseModel):
    agent_id: str
    key_id: str
    action: str
    parameters: dict = Field(default_factory=dict)
    delegation_id: str | None = None
    agent_signature: str
    ttl_seconds: int = Field(default=30, ge=5, le=60)


class AuthorityConsume(BaseModel):
    commitment_id: str
    action: str
    parameters: dict = Field(default_factory=dict)
    agent_signature: str


@router.post("/v1/agent-identity/tenants", summary="Create a tenant and its first owner membership")
async def create_tenant(req: TenantCreate, user: dict = Depends(get_verified_supabase_user)):
    user_id = _require_uuid(str(user.get("id") or ""), "verified_user_id")
    org_id = str(uuid.uuid4())
    created = _rpc_record(await _rpc("vgs_create_agent_identity_tenant", {
        "p_org_id": org_id, "p_user_id": user_id,
        "p_tenant_name": req.tenant_name.strip(),
    }))
    if not created:
        raise HTTPException(503, "Tenant creation was not committed; no owner membership was issued.")
    return {
        "tenant": created.get("tenant", {"org_id": org_id, "tenant_name": req.tenant_name.strip(), "status": "ACTIVE"}),
        "membership": created.get("membership", {"user_id": user_id, "org_id": org_id, "role": "owner", "status": "ACTIVE"}),
        "onboarding": "TENANT_OWNER_CREATED",
    }


@router.get("/v1/agent-identity/tenants", summary="List the authenticated user's active tenants")
async def list_my_tenants(user: dict = Depends(get_verified_supabase_user)):
    user_id = _require_uuid(str(user.get("id") or ""), "verified_user_id")
    memberships = await _select("vgs_agent_identity_memberships",
                                {"user_id": user_id, "status": "ACTIVE"}, limit=50)
    tenants = []
    for membership in memberships:
        tenant = await _one("vgs_agent_identity_tenants", {
            "org_id": str(membership["org_id"]), "status": "ACTIVE",
        })
        if tenant:
            tenants.append({"tenant": tenant, "membership": membership})
    return {"tenants": tenants}


@router.post("/v1/agent-identity/api-keys", summary="Create a tenant-scoped API key")
async def create_api_key(req: ApiKeyCreate, principal: Principal = Depends(get_principal)):
    _need(principal, "api_keys:write")
    _require_jwt_owner(principal)
    if ("api_keys:write" in req.scopes or not set(req.scopes).issubset(KNOWN_SCOPES)
            or not set(req.scopes).issubset(set(principal.scopes))):
        raise HTTPException(422, "Tenant API-key scopes must be valid, must not include api_keys:write, and cannot exceed the owner's scopes.")
    raw_key = "vsa_ak_" + secrets.token_urlsafe(36)
    key_id = str(uuid.uuid4())
    expires_at = _iso(_now() + timedelta(days=req.expires_in_days))
    await _insert("vgs_agent_identity_api_keys", {
        "key_id": key_id, "org_id": principal.org_id,
        "key_hash": hashlib.sha256(raw_key.encode()).hexdigest(),
        "key_prefix": raw_key[:14], "name": req.name, "scopes": req.scopes,
        "status": "ACTIVE", "created_by": principal.principal_id,
        "expires_at": expires_at,
    })
    return {"key_id": key_id, "api_key": raw_key, "name": req.name,
            "scopes": req.scopes, "expires_at": expires_at,
            "warning": "This key is shown once. Store it securely; VeriSigil stores only its SHA-256 hash."}


@router.post("/v1/agent-identity/api-keys/{key_id}/revoke", summary="Revoke a tenant API key")
async def revoke_api_key(key_id: str, principal: Principal = Depends(get_principal)):
    _need(principal, "api_keys:write")
    _require_jwt_owner(principal)
    key_id = _require_uuid(key_id, "key_id")
    row = await _one("vgs_agent_identity_api_keys", {
        "org_id": principal.org_id, "key_id": key_id,
    })
    if not row:
        raise HTTPException(404, "Tenant API key not found.")
    if row.get("status") != "ACTIVE":
        return {"key_id": key_id, "revoked": False, "status": row.get("status")}
    updated = await _patch("vgs_agent_identity_api_keys", {
        "org_id": principal.org_id, "key_id": key_id, "status": "ACTIVE",
    }, {"status": "REVOKED", "revoked_at": _iso()})
    if not updated:
        raise HTTPException(503, "Tenant API-key revocation was not confirmed by the database.")
    return {"key_id": key_id, "revoked": True, "status": "REVOKED"}


@router.post("/v1/agent-identity/challenges", summary="Issue an agent-key proof-of-possession challenge")
async def create_challenge(req: ChallengeCreate, principal: Principal = Depends(get_principal)):
    _need(principal, "agents:write" if req.purpose == "REGISTER_AGENT" else "keys:write")
    fingerprint = _fingerprint(req.public_key)
    if req.purpose == "REGISTER_AGENT" and req.agent_id is not None:
        raise HTTPException(422, "REGISTER_AGENT challenges cannot include an agent_id.")
    if req.purpose == "ROTATE_KEY":
        if not req.agent_id:
            raise HTTPException(422, "ROTATE_KEY challenges require agent_id.")
        await _get_agent(principal.org_id, req.agent_id)
    challenge = {
        "challenge_id": str(uuid.uuid4()), "org_id": principal.org_id,
        "purpose": req.purpose, "agent_id": req.agent_id,
        "key_fingerprint": fingerprint, "nonce": secrets.token_urlsafe(32),
        "expires_at": _iso(_now() + timedelta(minutes=5)),
    }
    await _insert("vgs_agent_identity_challenges", challenge)
    return {"challenge_id": challenge["challenge_id"], "nonce": challenge["nonce"],
            "org_id": challenge["org_id"], "key_fingerprint": fingerprint,
            "purpose": req.purpose, "agent_id": req.agent_id,
            "expires_at": challenge["expires_at"],
            "sign_this_exact_object": _challenge_payload(challenge),
            "algorithm": "Ed25519", "canonicalization": "RFC8785-JCS"}


@router.post("/v1/agent-identity/agents", summary="Register an agent and issue its Cryptographic Passport")
async def register_agent(req: AgentCreate, principal: Principal = Depends(get_principal)):
    _need(principal, "agents:write")
    if not req.capabilities or any(not ACTION_RE.fullmatch(x) for x in req.capabilities):
        raise HTTPException(422, "Capabilities must be unique action identifiers.")
    if len(set(req.capabilities)) != len(req.capabilities):
        raise HTTPException(422, "Duplicate capabilities are not permitted.")
    fingerprint = _fingerprint(req.public_key)
    challenge = await _consume_challenge(principal, req.challenge_id, "REGISTER_AGENT",
                                         None, req.public_key, req.proof_of_possession)
    agent_id = str(uuid.uuid4())
    did = f"did:web:verisigilai.com:agents:{agent_id}"
    issued_at = _iso()
    expires_at = _iso(_now() + timedelta(days=req.expires_in_days))
    passport = _passport(agent_id, principal.org_id, req.agent_name, did,
                         req.capabilities, [fingerprint], issued_at, expires_at)
    agent = {
        "agent_id": agent_id, "org_id": principal.org_id, "agent_name": req.agent_name,
        "did": did, "passport": passport, "capabilities": req.capabilities,
        "status": "ACTIVE", "issued_at": issued_at, "expires_at": expires_at,
    }
    key = {
        "key_id": fingerprint, "org_id": principal.org_id, "agent_id": agent_id,
        "public_key_b64": req.public_key, "fingerprint": fingerprint,
        "algorithm": "Ed25519", "status": "ACTIVE",
    }
    created = _rpc_record(await _rpc("vgs_create_agent_identity", {
        "p_agent": agent, "p_key": key,
    }))
    if not created:
        raise HTTPException(503, "Agent registration was not committed; no passport was issued.")
    return {"agent": created.get("agent", agent), "key": created.get("key", key),
            "passport": passport, "proof_of_possession": "VERIFIED",
            "challenge_id": challenge["challenge_id"]}


@router.get("/v1/agent-identity/agents", summary="List tenant agent identities")
async def list_agents(principal: Principal = Depends(get_principal)):
    _need(principal, "agents:read")
    return {"agents": await _select("vgs_agent_identities", {"org_id": principal.org_id}, limit=200)}


@router.get("/v1/agent-identity/agents/{agent_id}", summary="Inspect an agent and its passport")
async def get_agent(agent_id: str, principal: Principal = Depends(get_principal)):
    _need(principal, "agents:read")
    agent = await _get_agent(principal.org_id, agent_id)
    keys = await _select("vgs_agent_identity_keys", {"org_id": principal.org_id, "agent_id": agent_id}, limit=50)
    passport = agent.get("passport") or {}
    claims = passport.get("claims") or {}
    return {"agent": agent, "keys": keys,
            "passport_signature_valid": _passport_valid(agent),
            "passport_status": "VALID" if _agent_is_active(agent) and _passport_valid(agent) else "INVALID_OR_INACTIVE",
            "passport": passport, "issuer": claims.get("issuer")}


@router.post("/v1/agent-identity/agents/{agent_id}/keys", summary="Rotate an agent Ed25519 key")
async def rotate_agent_key(agent_id: str, req: KeyRotate, principal: Principal = Depends(get_principal)):
    _need(principal, "keys:write")
    agent = await _get_agent(principal.org_id, agent_id)
    if not _agent_is_active(agent) or not _passport_valid(agent):
        raise HTTPException(409, "Only an active agent with a valid issuer passport can rotate keys.")
    challenge = await _consume_challenge(principal, req.challenge_id, "ROTATE_KEY",
                                         agent_id, req.public_key, req.proof_of_possession)
    fingerprint = _fingerprint(req.public_key)
    old_claims = (agent.get("passport") or {}).get("claims") or {}
    fingerprints = list(old_claims.get("public_key_fingerprints") or [])
    if fingerprint in fingerprints:
        raise HTTPException(409, "This public key is already present in the passport.")
    fingerprints.append(fingerprint)
    now = _iso()
    claims = dict(old_claims)
    claims.update({"passport_version": int(old_claims.get("passport_version", 1)) + 1,
                   "public_key_fingerprints": fingerprints, "issued_at": now})
    passport = {"claims": claims, "issuer_signature": core.sign_governance_payload(claims)}
    key = {"key_id": fingerprint, "org_id": principal.org_id, "agent_id": agent_id,
           "public_key_b64": req.public_key, "fingerprint": fingerprint,
           "algorithm": "Ed25519", "status": "ACTIVE"}
    result = _rpc_record(await _rpc("vgs_rotate_agent_identity_key", {
        "p_org_id": principal.org_id, "p_agent_id": agent_id,
        "p_key": key, "p_passport": passport, "p_replace_existing": req.replace_existing,
    }))
    if not result:
        raise HTTPException(503, "Key rotation was not committed.")
    return {"agent_id": agent_id, "key": result.get("key", key),
            "passport": passport, "proof_of_possession": "VERIFIED",
            "previous_keys": "ROTATED" if req.replace_existing else "UNCHANGED",
            "challenge_id": challenge["challenge_id"]}


@router.post("/v1/agent-identity/keys/{key_id}/revoke", summary="Revoke an agent public key")
async def revoke_agent_key(key_id: str, principal: Principal = Depends(get_principal)):
    _need(principal, "keys:write")
    if not re.fullmatch(r"[0-9a-f]{64}", key_id):
        raise HTTPException(422, "key_id must be a SHA-256 Ed25519 fingerprint.")
    key = await _one("vgs_agent_identity_keys", {"org_id": principal.org_id, "key_id": key_id})
    if not key:
        raise HTTPException(404, "Agent key not found in this tenant.")
    if key.get("status") != "ACTIVE":
        return {"revoked": False, "status": key.get("status"), "key_id": key_id}
    updated = await _patch("vgs_agent_identity_keys", {
        "org_id": principal.org_id, "key_id": key_id, "status": "ACTIVE",
    }, {"status": "REVOKED", "revoked_at": _iso()})
    if not updated:
        raise HTTPException(503, "Agent-key revocation was not confirmed by the database.")
    return {"revoked": True, "key_id": key_id, "status": "REVOKED"}


@router.post("/v1/agent-identity/agents/{agent_id}/revoke", summary="Revoke an agent and its downstream authority")
async def revoke_agent(agent_id: str, principal: Principal = Depends(get_principal)):
    _need(principal, "agents:revoke")
    await _get_agent(principal.org_id, agent_id)
    result = _rpc_record(await _rpc("vgs_revoke_agent_identity", {
        "p_org_id": principal.org_id, "p_agent_id": agent_id,
    }))
    if not result:
        raise HTTPException(503, "Agent revocation was not confirmed by the database.")
    return {"agent_id": agent_id, "status": "REVOKED",
            "revoked_keys": result.get("revoked_keys", 0),
            "revoked_delegations": result.get("revoked_delegations", 0)}


@router.post("/v1/agent-identity/delegations", summary="Create a bounded agent-to-agent delegation")
async def create_delegation(req: DelegationCreate, principal: Principal = Depends(get_principal)):
    _need(principal, "delegations:write")
    if not req.scopes or len(set(req.scopes)) != len(req.scopes) or any(not ACTION_RE.fullmatch(x) for x in req.scopes):
        raise HTTPException(422, "Delegation scopes must be unique action identifiers.")
    grantor = await _get_agent(principal.org_id, req.grantor_agent_id)
    grantee = await _get_agent(principal.org_id, req.grantee_agent_id)
    if req.grantor_agent_id == req.grantee_agent_id:
        raise HTTPException(422, "An agent cannot delegate authority to itself.")
    if not _agent_is_active(grantor) or not _agent_is_active(grantee) or not _passport_valid(grantor) or not _passport_valid(grantee):
        raise HTTPException(409, "Both agents must have active, valid passports.")
    grantor_caps = ((grantor.get("passport") or {}).get("claims") or {}).get("declared_capabilities") or []
    if not set(req.scopes).issubset(set(grantor_caps)):
        raise HTTPException(403, "Delegated scopes cannot exceed the grantor's declared capabilities.")
    try:
        expiry = _parse_time(req.expires_at)
    except Exception as exc:
        raise HTTPException(422, "expires_at must be an ISO-8601 timestamp.") from exc
    if expiry <= _now() or expiry > min(_parse_time(grantor["expires_at"]), _parse_time(grantee["expires_at"])):
        raise HTTPException(422, "Delegation expiry must be future-dated and no later than either agent passport.")
    delegation = {
        "delegation_id": str(uuid.uuid4()), "org_id": principal.org_id,
        "grantor_agent_id": req.grantor_agent_id, "grantee_agent_id": req.grantee_agent_id,
        "scopes": req.scopes, "status": "ACTIVE", "issued_at": _iso(),
        "expires_at": expiry.isoformat(),
    }
    return await _insert("vgs_agent_delegations", delegation)


@router.post("/v1/agent-identity/delegations/{delegation_id}/revoke", summary="Revoke a delegation")
async def revoke_delegation(delegation_id: str, principal: Principal = Depends(get_principal)):
    _need(principal, "delegations:write")
    delegation_id = _require_uuid(delegation_id, "delegation_id")
    row = await _one("vgs_agent_delegations", {
        "org_id": principal.org_id, "delegation_id": delegation_id,
    })
    if not row:
        raise HTTPException(404, "Delegation not found in this tenant.")
    updated = await _patch("vgs_agent_delegations", {
        "org_id": principal.org_id, "delegation_id": delegation_id, "status": "ACTIVE",
    }, {"status": "REVOKED", "revoked_at": _iso()})
    if not updated:
        raise HTTPException(503, "Delegation revocation was not confirmed by the database.")
    return {"delegation_id": delegation_id, "status": "REVOKED"}


@router.post("/v1/runtime/authority/evaluate", summary="Evaluate current authority for exact action parameters")
async def evaluate_authority(req: AuthorityEvaluate, principal: Principal = Depends(get_principal)):
    _need(principal, "authority:evaluate")
    if not ACTION_RE.fullmatch(req.action):
        raise HTTPException(422, "action must be a stable lower-case action identifier.")
    try:
        parameter_bytes = _canonical(req.parameters)
    except Exception as exc:
        raise HTTPException(422, "parameters are not RFC 8785 canonicalizable JSON.") from exc
    if len(parameter_bytes) > MAX_PARAMETERS_BYTES:
        raise HTTPException(413, "Action parameters exceed the 64 KiB authority-evaluation limit.")
    agent = await _get_agent(principal.org_id, req.agent_id)
    key = await _get_key(principal.org_id, req.agent_id, req.key_id)
    action_payload = _runtime_action_payload(req.agent_id, req.key_id, req.action,
                                             req.parameters, req.delegation_id)
    if not _verify_agent_signature(key["public_key_b64"], action_payload, req.agent_signature):
        raise HTTPException(401, "Agent key proof-of-possession failed for this exact action.")
    _, _, reasons = await _evaluate_identity(principal.org_id, req.agent_id, req.key_id,
                                              req.action, req.delegation_id)
    action_digest = _digest(action_payload)
    commitment_id = str(uuid.uuid4())
    expires_at = _iso(_now() + timedelta(seconds=req.ttl_seconds))
    decision = "AUTHORIZED" if not reasons else "REFUSED"
    signed_decision = {
        "schema": "VERISIGIL-RUNTIME-AUTHORITY-1.0",
        "commitment_id": commitment_id, "org_id": principal.org_id,
        "agent_id": req.agent_id, "key_id": req.key_id,
        "delegation_id": req.delegation_id, "action": req.action,
        "action_digest": action_digest, "decision": decision,
        "reasons": reasons, "evaluated_at": _iso(), "expires_at": expires_at,
        "execution": "NOT_EXECUTED",
    }
    decision_receipt = {**signed_decision,
                        "issuer_signature": core.sign_governance_payload(signed_decision)}
    await _insert("vgs_agent_authority_commitments", {
        "commitment_id": commitment_id, "org_id": principal.org_id,
        "agent_id": req.agent_id, "key_id": req.key_id,
        "delegation_id": req.delegation_id, "action": req.action,
        "action_digest": action_digest, "parameters": req.parameters,
        "decision": decision, "reasons": reasons, "expires_at": expires_at,
        "decision_receipt": decision_receipt,
    })
    return {"commitment_id": commitment_id, "decision": decision,
            "reasons": reasons, "action_digest": action_digest,
            "expires_at": expires_at, "decision_receipt": decision_receipt,
            "execution_authorized": False, "actuator_invoked": False,
            "next_step": "Consume the one-time commitment at the protected actuator boundary." if decision == "AUTHORIZED" else "Repair identity or authority; do not execute."}


@router.post("/v1/runtime/authority/consume", summary="Atomically consume an authority commitment once")
async def consume_authority(req: AuthorityConsume, principal: Principal = Depends(get_principal)):
    _need(principal, "authority:consume")
    commitment_id = _require_uuid(req.commitment_id, "commitment_id")
    commitment_id = _require_uuid(commitment_id, "commitment_id")
    row = await _one("vgs_agent_authority_commitments", {
        "org_id": principal.org_id, "commitment_id": commitment_id,
    })
    if not row:
        raise HTTPException(404, "Authority commitment not found in this tenant.")
    if row.get("decision") != "AUTHORIZED":
        raise HTTPException(403, "A refused authority decision cannot be consumed.")
    payload = _runtime_action_payload(row["agent_id"], row["key_id"], req.action,
                                      req.parameters, row.get("delegation_id"))
    action_digest = _digest(payload)
    if action_digest != row.get("action_digest") or req.action != row.get("action"):
        raise HTTPException(409, "Exact action parameters do not match the evaluated commitment.")
    agent = await _get_agent(principal.org_id, row["agent_id"])
    key = await _get_key(principal.org_id, row["agent_id"], row["key_id"])
    proof_payload = {
        "commitment_id": req.commitment_id, "action_digest": action_digest,
        "agent_id": row["agent_id"], "key_id": row["key_id"],
    }
    if not _verify_agent_signature(key["public_key_b64"], proof_payload, req.agent_signature):
        raise HTTPException(401, "Agent key proof-of-possession failed at the consume boundary.")
    _, _, reasons = await _evaluate_identity(principal.org_id, row["agent_id"], row["key_id"],
                                              row["action"], row.get("delegation_id"))
    if reasons:
        raise HTTPException(403, {"error": "AUTHORITY_REVOKED_BEFORE_CONSUME", "reasons": reasons})
    consumed_at = _iso()
    receipt_claims = {
        "schema": "VERISIGIL-EXECUTION-AUTHORITY-RECEIPT-1.0",
        "commitment_id": req.commitment_id, "org_id": principal.org_id,
        "agent_id": row["agent_id"], "key_id": row["key_id"],
        "delegation_id": row.get("delegation_id"), "action": row["action"],
        "action_digest": action_digest, "decision": "AUTHORIZED",
        "consumed_at": consumed_at, "actuator_invoked": False,
    }
    receipt = {**receipt_claims,
               "issuer_signature": core.sign_governance_payload(receipt_claims)}
    consumed = _rpc_record(await _rpc("vgs_consume_agent_authority_commitment", {
        "p_commitment_id": req.commitment_id, "p_org_id": principal.org_id,
        "p_action_digest": action_digest, "p_consumed_at": consumed_at,
        "p_consumption_receipt": receipt,
    }))
    if not consumed:
        raise HTTPException(409, "Authority commitment expired, was revoked, or has already been consumed.")
    return {"commitment_id": req.commitment_id, "execution_authorized": True,
            "actuator_invoked": False, "receipt": receipt,
            "message": "One-time authority and signed receipt were atomically persisted. The caller's protected actuator must enforce this result."}



@router.get("/v1/runtime/authority/receipts/{commitment_id}", summary="Retrieve a tenant execution-authority receipt")
async def get_authority_receipt(commitment_id: str, principal: Principal = Depends(get_principal)):
    _need(principal, "receipts:read")
    row = await _one("vgs_agent_authority_commitments", {
        "org_id": principal.org_id, "commitment_id": commitment_id,
    })
    if not row:
        raise HTTPException(404, "Authority receipt not found in this tenant.")
    receipt = row.get("consumption_receipt") or row.get("decision_receipt")
    if not receipt:
        raise HTTPException(404, "No receipt has been issued for this commitment.")
    signature = receipt.get("issuer_signature", "")
    claims = {key: value for key, value in receipt.items() if key != "issuer_signature"}
    consumable = False
    current_reasons = []
    if row.get("decision") == "AUTHORIZED" and not row.get("consumed_at") and _parse_time(row["expires_at"]) > _now():
        _, _, current_reasons = await _evaluate_identity(
            principal.org_id, row["agent_id"], row["key_id"],
            row["action"], row.get("delegation_id"),
        )
        consumable = not current_reasons
    return {"receipt": receipt,
            "issuer_signature_valid": core.verify_governance_signature(claims, signature),
            "consumed": bool(row.get("consumed_at")),
            "current_decision": row.get("decision"),
            "consumable": consumable,
            "current_authority_reasons": current_reasons}


def install_openapi_security(app) -> None:
    """Document the two supported auth modes for this router in Swagger."""
    previous_openapi = app.openapi

    def _openapi():
        schema = previous_openapi()
        schemes = schema.setdefault("components", {}).setdefault("securitySchemes", {})
        schemes["SupabaseBearer"] = {
            "type": "http", "scheme": "bearer",
            "bearerFormat": "Supabase JWT",
            "description": "A Supabase access token. The API verifies it through Supabase Auth and resolves an active tenant membership.",
        }
        for path, operations in schema.get("paths", {}).items():
            if path.startswith("/v1/agent-identity/") or path.startswith("/v1/runtime/authority/"):
                for operation in operations.values():
                    if isinstance(operation, dict) and "operationId" in operation:
                        if path in {"/v1/agent-identity/api-keys", "/v1/agent-identity/tenants"} or path.startswith("/v1/agent-identity/api-keys/"):
                            operation["security"] = [{"SupabaseBearer": []}]
                        else:
                            operation["security"] = [{"SupabaseBearer": []}, {"ApiKeyAuth": []}]
        return schema

    app.openapi_schema = None
    app.openapi = _openapi
