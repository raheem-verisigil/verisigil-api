"""Fail-closed Supabase persistence for VGS revalidation receipts.

The service-role key is read only from SUPABASE_KEY at runtime. No local
fallback is permitted: inability to persist, retrieve, or atomically consume
a receipt must prevent execution authorization.
"""
from __future__ import annotations

import os
from typing import Any

import httpx


class ReceiptPersistenceUnavailable(RuntimeError):
    """Raised when durable receipt storage cannot be trusted."""


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
    payload = {
        "revalidation_id": revalidation_id,
        "proposal_id": proposal_id,
        "receipt": receipt,
        "record": record,
    }
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.post(
                f"{base}/rest/v1/vgs_validation_receipts",
                headers=_headers(key, "return=minimal"),
                json=payload,
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
    """Atomically consume a one-time receipt using the database RPC.

    The SQL function updates only rows with consumed_at IS NULL and the exact
    proposal ID. Concurrent replicas therefore race on one database row;
    only one can receive the record.
    """
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
