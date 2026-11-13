"""Fail-closed Supabase persistence and one-time consumption of VGS receipts."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse


class ReceiptPersistenceUnavailable(RuntimeError):
    """Durable receipt state cannot be trusted."""


def _config() -> tuple[str, str]:
    base = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
    key = os.environ.get("SUPABASE_KEY", "").strip()
    if not base.startswith("https://") or not key:
        raise ReceiptPersistenceUnavailable("Supabase durable receipt storage is not configured.")
    return base, key


def _headers(key: str, prefer: str | None = None) -> dict[str, str]:
    headers = {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if prefer:
        headers["Prefer"] = prefer
    return headers


async def persist_validation_receipt(revalidation_id: str, proposal_id: str,
                                     receipt: dict[str, Any], record: dict[str, Any]) -> None:
    base, key = _config()
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.post(
                f"{base}/rest/v1/vgs_validation_receipts",
                headers=_headers(key, "return=minimal"),
                json={
                    "revalidation_id": revalidation_id,
                    "proposal_id": proposal_id,
                    "receipt": receipt,
                    "record": record,
                },
            )
        if response.status_code not in (200, 201, 204):
            raise ReceiptPersistenceUnavailable(
                f"Supabase receipt insert rejected (HTTP {response.status_code})."
            )
    except ReceiptPersistenceUnavailable:
        raise
    except Exception as exc:
        raise ReceiptPersistenceUnavailable("Supabase receipt insert failed.") from exc


async def load_validation_receipt(revalidation_id: str) -> dict[str, Any] | None:
    base, key = _config()
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.get(
                f"{base}/rest/v1/vgs_validation_receipts",
                headers=_headers(key),
                params={
                    "select": "revalidation_id,proposal_id,receipt,record,consumed_at",
                    "revalidation_id": f"eq.{revalidation_id}",
                    "limit": "1",
                },
            )
        if response.status_code != 200:
            raise ReceiptPersistenceUnavailable(
                f"Supabase receipt read rejected (HTTP {response.status_code})."
            )
        rows = response.json()
        if not isinstance(rows, list):
            raise ReceiptPersistenceUnavailable("Supabase receipt read returned an invalid shape.")
        return rows[0] if rows else None
    except ReceiptPersistenceUnavailable:
        raise
    except Exception as exc:
        raise ReceiptPersistenceUnavailable("Supabase receipt read failed.") from exc


async def consume_validation_receipt(revalidation_id: str, proposal_id: str) -> dict[str, Any] | None:
    """Atomically consume one receipt. The database RPC serializes replicas."""
    base, key = _config()
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.post(
                f"{base}/rest/v1/rpc/vgs_consume_validation_receipt",
                headers=_headers(key),
                json={
                    "p_revalidation_id": revalidation_id,
                    "p_proposal_id": proposal_id,
                },
            )
        if response.status_code != 200:
            raise ReceiptPersistenceUnavailable(
                f"Supabase atomic receipt consume rejected (HTTP {response.status_code})."
            )
        result = response.json()
        if result is None:
            return None
        if not isinstance(result, dict):
            raise ReceiptPersistenceUnavailable("Supabase consume RPC returned an invalid shape.")
        return result
    except ReceiptPersistenceUnavailable:
        raise
    except Exception as exc:
        raise ReceiptPersistenceUnavailable("Supabase atomic receipt consume failed.") from exc


def install_durable_middleware(app, core, receipt_cache, authority_check,
                               capacity_check, now_fn, signed_receipt):
    """Persist revalidation results and gate execution using durable one-time receipts."""

    @app.middleware("http")
    async def durable_receipt_boundary(request: Request, call_next):
        path = request.url.path

        if request.method == "POST" and path == "/v1/revalidation/check":
            response = await call_next(request)
            if response.status_code != 200:
                return response
            try:
                payload = __import__("json").loads(response.body)
            except Exception:
                return JSONResponse({
                    "ruling": "DURABLE_RECEIPT_INVALID",
                    "allowed": False,
                    "consequence_boundary": "NO_EXECUTION_AUTHORIZATION_ISSUED",
                }, status_code=503)
            rid = payload.get("revalidation_id")
            proposal_id = payload.get("proposal_id")
            if not rid or not proposal_id:
                return response
            record = receipt_cache.get(rid)
            if not isinstance(record, dict):
                return JSONResponse({
                    "revalidation_id": rid,
                    "proposal_id": proposal_id,
                    "ruling": "DURABLE_RECEIPT_RECORD_MISSING",
                    "allowed": False,
                    "consequence_boundary": "NO_EXECUTION_AUTHORIZATION_ISSUED",
                }, status_code=503)
            durable_record = dict(record)
            durable_record["ruling"] = payload.get("ruling", "")
            durable_record["allowed"] = bool(payload.get("allowed", payload.get("ruling") == "ALLOW"))
            try:
                await persist_validation_receipt(rid, proposal_id, payload, durable_record)
            except ReceiptPersistenceUnavailable:
                return JSONResponse({
                    "revalidation_id": rid,
                    "proposal_id": proposal_id,
                    "ruling": "DURABLE_RECEIPT_STORAGE_UNAVAILABLE",
                    "allowed": False,
                    "reason": "Revalidation result was not durably stored; execution authorization is unavailable.",
                    "checked_at": now_fn(),
                    "consequence_boundary": "NO_EXECUTION_AUTHORIZATION_ISSUED",
                }, status_code=503)
            receipt_cache[rid] = durable_record
            return response

        if request.method == "POST" and path == "/v1/execution/authorize":
            try:
                core.require_api_key(
                    request.headers.get("x-api-key"),
                    request.headers.get("authorization"),
                )
            except HTTPException as exc:
                return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

            try:
                req = await request.json()
            except Exception:
                return JSONResponse({"error": "INVALID_JSON"}, status_code=400)

            rid = req.get("revalidation_id", "")
            proposal_id = req.get("proposal_id", "")
            try:
                stored = await load_validation_receipt(rid)
            except ReceiptPersistenceUnavailable:
                return JSONResponse({
                    "revalidation_id": rid,
                    "proposal_id": proposal_id,
                    "ruling": "DURABLE_RECEIPT_STORE_UNAVAILABLE",
                    "allowed": False,
                    "reason": "Durable receipt state cannot be verified.",
                    "checked_at": now_fn(),
                    "consequence_boundary": "NO_EXECUTION_AUTHORIZATION_ISSUED",
                }, status_code=503)

            if not stored:
                return JSONResponse({
                    "revalidation_id": rid,
                    "proposal_id": proposal_id,
                    "ruling": "REVALIDATION_RECEIPT_MISSING",
                    "allowed": False,
                    "consequence_boundary": "NO_EXECUTION_AUTHORIZATION_ISSUED",
                }, status_code=403)

            record = stored.get("record")
            receipt = stored.get("receipt")
            if not isinstance(record, dict) or not isinstance(receipt, dict):
                return JSONResponse({
                    "revalidation_id": rid,
                    "proposal_id": proposal_id,
                    "ruling": "REVALIDATION_RECEIPT_INVALID",
                    "allowed": False,
                    "consequence_boundary": "NO_EXECUTION_AUTHORIZATION_ISSUED",
                }, status_code=403)

            if stored.get("proposal_id") != proposal_id or record.get("proposal_id") != proposal_id:
                return JSONResponse({
                    "revalidation_id": rid,
                    "proposal_id": proposal_id,
                    "ruling": "REVALIDATION_PROPOSAL_MISMATCH",
                    "allowed": False,
                    "consequence_boundary": "NO_EXECUTION_AUTHORIZATION_ISSUED",
                }, status_code=403)

            signature = receipt.get("governance_signature", "")
            unsigned = dict(receipt)
            unsigned.pop("governance_signature", None)
            if not signature or not core.verify_governance_signature(unsigned, signature):
                return JSONResponse({
                    "revalidation_id": rid,
                    "proposal_id": proposal_id,
                    "ruling": "REVALIDATION_RECEIPT_SIGNATURE_INVALID",
                    "allowed": False,
                    "consequence_boundary": "NO_EXECUTION_AUTHORIZATION_ISSUED",
                }, status_code=403)

            if record.get("allowed") is not True or record.get("ruling") != "ALLOW":
                return JSONResponse({
                    "revalidation_id": rid,
                    "proposal_id": proposal_id,
                    "ruling": "REVALIDATION_NOT_ALLOWED",
                    "allowed": False,
                    "consequence_boundary": "NO_EXECUTION_AUTHORIZATION_ISSUED",
                }, status_code=403)

            if stored.get("consumed_at"):
                return JSONResponse({
                    "revalidation_id": rid,
                    "proposal_id": proposal_id,
                    "ruling": "REVALIDATION_RECEIPT_ALREADY_CONSUMED",
                    "allowed": False,
                    "consequence_boundary": "NO_EXECUTION_AUTHORIZATION_ISSUED",
                }, status_code=403)

            try:
                consumed = await consume_validation_receipt(rid, proposal_id)
            except ReceiptPersistenceUnavailable:
                return JSONResponse({
                    "revalidation_id": rid,
                    "proposal_id": proposal_id,
                    "ruling": "ATOMIC_RECEIPT_CONSUME_UNAVAILABLE",
                    "allowed": False,
                    "checked_at": now_fn(),
                    "consequence_boundary": "NO_EXECUTION_AUTHORIZATION_ISSUED",
                }, status_code=503)
            if not consumed:
                return JSONResponse({
                    "revalidation_id": rid,
                    "proposal_id": proposal_id,
                    "ruling": "REVALIDATION_RECEIPT_ALREADY_CONSUMED",
                    "allowed": False,
                    "reason": "Another request consumed this receipt first.",
                    "checked_at": now_fn(),
                    "consequence_boundary": "NO_EXECUTION_AUTHORIZATION_ISSUED",
                }, status_code=403)

            record = consumed
            authority = authority_check(
                record["agent_id"], record["action_type"], record.get("amount")
            )
            capacity = capacity_check(
                record["capacity_assertion_id"], record.get("required_capacity")
            )
            authority_unchanged = authority.get("passport_id") == record.get("passport_id")
            if not authority.get("valid") or not authority_unchanged or not capacity.get("valid"):
                ts = now_fn()
                blocked = signed_receipt({
                    "schema": "VGS-EXECUTION-AUTH-BLOCK-1.0",
                    "revalidation_id": rid,
                    "proposal_id": proposal_id,
                    "ruling": "AUTHORITY_INVALID" if not authority.get("valid") or not authority_unchanged else capacity.get("ruling"),
                    "allowed": False,
                    "authority": authority,
                    "capacity": capacity,
                    "authority_unchanged_since_revalidation": authority_unchanged,
                    "checked_at": ts,
                    "consequence_boundary": "NO_EXECUTION_AUTHORIZATION_ISSUED",
                })
                return JSONResponse(blocked, status_code=403)

            result = await core.execution_authorize(
                req,
                x_api_key=request.headers.get("x-api-key"),
                authorization=request.headers.get("authorization"),
            )
            ttl = req.get("ttl_seconds", 30)
            if not isinstance(ttl, int) or isinstance(ttl, bool):
                ttl = 30
            ttl = max(1, min(ttl, 300))
            issued_at = datetime.now(timezone.utc)
            result["issued_at"] = issued_at.isoformat()
            result["expires_at"] = (issued_at + timedelta(seconds=ttl)).isoformat()
            result["ttl_seconds"] = ttl
            result["commit_time_recheck"] = {"authority": authority, "capacity": capacity}
            result["consequence_boundary"] = "PRE_EXECUTION_AUTHORIZATION_ONLY"
            result.pop("governance_signature", None)
            result["governance_signature"] = core.sign_governance_payload(result)
            core._EXECUTION_AUTH[result["execution_auth_id"]] = result
            return JSONResponse(result)

        return await call_next(request)
