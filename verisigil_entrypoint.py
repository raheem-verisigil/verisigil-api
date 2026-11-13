"""Staging entrypoint: hardens public proof verification and VGS revalidation."""
from __future__ import annotations

import hashlib
import json
import math
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse

import main as core
from proof_verification import public_key_id, verify_ed25519_payload

app = core.app
VALIDATION_RECEIPTS: dict[str, dict] = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _signed_receipt(body: dict) -> dict:
    receipt = dict(body)
    receipt["governance_signature"] = core.sign_governance_payload(receipt)
    return receipt


def _finite_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value))


def _capacity_check(assertion_id: str, required_override: Any = None) -> dict:
    assertion = core._STATE_ASSERTIONS.get(assertion_id)
    if not assertion:
        return {"valid": False, "ruling": "STATE_INVALID", "reason": "Capacity state assertion not found."}
    related = [
        item for item in core._STATE_ASSERTIONS.values()
        if item.get("subject") == assertion.get("subject") and item.get("state_type") == assertion.get("state_type")
    ]
    if related:
        latest = max(related, key=lambda item: item.get("issued_at", ""))
        if latest.get("assertion_id") != assertion_id:
            return {"valid": False, "ruling": "CAPACITY_STALE", "reason": "A newer capacity assertion superseded this evidence."}

    state = assertion.get("state")
    if not isinstance(state, dict):
        return {"valid": False, "ruling": "STATE_INVALID", "reason": "Capacity state must be a JSON object."}
    actual_hash = hashlib.sha256(_canonical(state)).hexdigest()
    if actual_hash != assertion.get("state_hash"):
        return {"valid": False, "ruling": "STATE_INVALID", "reason": "State assertion hash mismatch."}
    signed_fields = {"assertion_id": assertion.get("assertion_id"), "state_hash": assertion.get("state_hash"), "timestamp": assertion.get("issued_at")}
    if not core.verify_governance_signature(signed_fields, assertion.get("governance_signature", "")):
        return {"valid": False, "ruling": "STATE_INVALID", "reason": "VeriSigil state receipt signature is invalid."}
    now = datetime.now(timezone.utc)
    issued_at = assertion.get("issued_at")
    try:
        issued = datetime.fromisoformat(str(issued_at).replace("Z", "+00:00"))
        if issued.tzinfo is None:
            issued = issued.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return {"valid": False, "ruling": "STATE_INVALID", "reason": "State assertion issue time is malformed."}
    freshness_seconds = assertion.get("validation", {}).get("freshness_seconds", 300)
    if not _finite_number(freshness_seconds) or freshness_seconds <= 0 or (now - issued).total_seconds() > freshness_seconds:
        return {"valid": False, "ruling": "STATE_STALE", "reason": "Capacity state assertion exceeds its freshness window."}
    expires_at = assertion.get("expires_at") or ""
    if expires_at:
        try:
            expiry = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            return {"valid": False, "ruling": "STATE_INVALID", "reason": "State assertion expiry is malformed."}
        if now > expiry:
            return {"valid": False, "ruling": "STATE_INVALID", "reason": "Capacity state assertion has expired."}
    if assertion.get("state_type") != "capacity":
        return {"valid": False, "ruling": "CAPACITY_INVALID", "reason": "State assertion type is not capacity."}
    capacity = state.get("capacity")
    if not isinstance(capacity, dict):
        return {"valid": False, "ruling": "CAPACITY_INVALID", "reason": "State assertion has no capacity object."}
    total = capacity.get("total")
    obligations = state.get("obligations", [])
    if not isinstance(obligations, list):
        return {"valid": False, "ruling": "CAPACITY_INVALID", "reason": "Obligations must be an array."}
    seen_ids = set()
    obligation_total = 0.0
    for item in obligations:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item.get("id").strip():
            return {"valid": False, "ruling": "CAPACITY_INVALID", "reason": "Every obligation requires a stable string id."}
        if item["id"] in seen_ids:
            return {"valid": False, "ruling": "CAPACITY_INVALID", "reason": "Duplicate obligation id would double-count cumulative commitments."}
        seen_ids.add(item["id"])
        amount = item.get("amount")
        if not _finite_number(amount) or amount < 0:
            return {"valid": False, "ruling": "CAPACITY_INVALID", "reason": "Obligation amounts must be finite non-negative numbers."}
        obligation_total += float(amount)
    if not _finite_number(total) or total < 0:
        return {"valid": False, "ruling": "CAPACITY_INVALID", "reason": "Total capacity must be a finite non-negative number."}
    required = required_override if required_override is not None else capacity.get("required")
    if not _finite_number(required) or required < 0:
        return {"valid": False, "ruling": "CAPACITY_INVALID", "reason": "Required capacity must be a finite non-negative number."}
    available = float(total) - obligation_total
    common = {
        "assertion_id": assertion_id, "state_hash": actual_hash,
        "total_capacity": float(total), "cumulative_obligations": obligation_total,
        "obligation_count": len(obligations), "available_capacity": available,
        "required_capacity": float(required),
        "source_authentication": "NOT_INDEPENDENTLY_ESTABLISHED_BY_THIS_RECEIPT",
    }
    claimed_available = capacity.get("available")
    if claimed_available is not None and (not _finite_number(claimed_available) or abs(float(claimed_available) - available) > 1e-9):
        return {"valid": False, "ruling": "CAPACITY_CONTRADICTION", "reason": "Claimed available capacity conflicts with cumulative obligations.", **common}
    valid = available >= float(required)
    return {
        "valid": valid, "ruling": "ALLOW" if valid else "CAPACITY_INSUFFICIENT",
        "reason": "Capacity covers the required amount after cumulative obligations." if valid else "Unsupported consequence blocked: remaining capacity is below the required amount.",
        **common,
    }


def _authority_check(agent_id: str, action_type: str, amount: Any = None) -> dict:
    passport = core._DELEGATION_PASSPORTS.get(agent_id)
    if not passport:
        return {"valid": False, "ruling": "AUTHORITY_INVALID", "reason": "No active delegation passport found."}
    expires_at = passport.get("expires_at") or "9999-12-31T23:59:59+00:00"
    try:
        expiry = datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        not_expired = datetime.now(timezone.utc) <= expiry
    except (TypeError, ValueError):
        not_expired = False
    allowed = passport.get("allowed_actions", [])
    forbidden = passport.get("forbidden_actions", [])
    in_scope = action_type in allowed and action_type not in forbidden
    amount_within_limit = True
    budget_sufficient = True
    if amount is not None:
        max_value = passport.get("max_transaction_value", 0)
        remaining_budget = passport.get("budget_remaining", 0)
        amount_within_limit = _finite_number(amount) and _finite_number(max_value) and amount >= 0 and amount <= max_value
        budget_sufficient = _finite_number(amount) and _finite_number(remaining_budget) and amount >= 0 and amount <= remaining_budget
    valid = not passport.get("revoked", False) and not_expired and in_scope and amount_within_limit and budget_sufficient
    return {
        "valid": valid, "ruling": "ALLOW" if valid else "AUTHORITY_INVALID",
        "reason": "Authority is active and action is within scope and limits." if valid else "Authority is revoked, expired, missing, outside scope, or exceeds its delegated limits.",
        "passport_id": passport.get("passport_id", ""), "revoked": bool(passport.get("revoked", False)),
        "not_expired": not_expired, "action_in_scope": in_scope,
        "amount_within_limit": amount_within_limit, "budget_sufficient": budget_sufficient,
    }


@app.middleware("http")
async def verisigil_runtime_hardening(request: Request, call_next):
    if request.method == "POST" and request.url.path == "/v1/proof/verify":
        try:
            payload = await request.json()
        except Exception:
            return JSONResponse({"result": "UNVERIFIED", "message": "Request body must be valid JSON."}, status_code=400)
        signature = request.query_params.get("signature", "")
        key_id = request.query_params.get("key_id")
        public_key = __import__("base64").b64encode(bytes(core._VERIFY_KEY)).decode("ascii")
        revoked = {x.strip() for x in os.environ.get("ED25519_REVOKED_KEY_IDS", "").split(",") if x.strip()}
        result = verify_ed25519_payload(payload, signature, public_key, key_id, revoked)
        return JSONResponse({**result, "public_key": public_key, "key_id": public_key_id(public_key), "algorithm": "Ed25519", "timestamp": _now()})

    if request.method == "POST" and request.url.path == "/v1/revalidation/check":
        try:
            req = await request.json()
        except Exception:
            return JSONResponse({"error": "INVALID_JSON"}, status_code=400)
        proposal_id = req.get("proposal_id", "")
        proposal = core._PROPOSAL_REGISTRY.get(proposal_id)
        if proposal and (req.get("capacity_assertion_id") or req.get("state_assertion_id") or proposal.get("state", {}).get("canonical_state_assertion_id")):
            agent_id = req.get("agent_id", "")
            action_type = req.get("action_type", "")
            assertion_id = req.get("capacity_assertion_id") or req.get("state_assertion_id") or proposal.get("state", {}).get("canonical_state_assertion_id", "")
            authority = _authority_check(agent_id, action_type, req.get("amount", req.get("required_capacity")))
            capacity = _capacity_check(assertion_id, req.get("required_capacity"))
            failure = authority["ruling"] if not authority["valid"] else capacity["ruling"] if not capacity["valid"] else None
            if failure:
                ts = _now()
                rid = f"RVL-{hashlib.sha256((proposal_id + ts + failure).encode()).hexdigest()[:12].upper()}"
                receipt = _signed_receipt({
                    "schema": "VGS-REVALIDATION-1.1", "revalidation_id": rid,
                    "proposal_id": proposal_id, "agent_id": agent_id, "ruling": failure,
                    "allowed": False, "authority": authority, "capacity": capacity,
                    "revalidated_at": ts, "consequence_boundary": "NO_EXECUTION_AUTHORIZATION_ISSUED",
                })
                core._REVALIDATION_LOG.append({"revalidation_id": rid, "ruling": failure, "at": ts})
                VALIDATION_RECEIPTS[rid] = {
                    "agent_id": agent_id, "action_type": action_type, "proposal_id": proposal_id,
                    "capacity_assertion_id": assertion_id, "required_capacity": req.get("required_capacity"),
                    "amount": req.get("amount", req.get("required_capacity")),
                    "passport_id": authority.get("passport_id", ""),
                }
                core._emit_proof_event("REVALIDATION_FAILED", rid, {"ruling": failure, "proposal_id": proposal_id}, ts)
                return JSONResponse(receipt)
            result = await core.revalidation_check(req, x_api_key=request.headers.get("x-api-key"), authorization=request.headers.get("authorization"))
            result["schema"] = "VGS-REVALIDATION-1.1"
            result["authority"] = authority
            result["capacity"] = capacity
            result["checks"]["capacity_evidence_valid"] = True
            result["checks"]["cumulative_obligations_accounted"] = True
            result["checks"]["authority_scope_valid"] = True
            result["consequence_boundary"] = "PRE_EXECUTION_AUTHORIZATION_ONLY"
            result.pop("governance_signature", None)
            result["governance_signature"] = core.sign_governance_payload(result)
            VALIDATION_RECEIPTS[result["revalidation_id"]] = {
                "agent_id": agent_id, "action_type": action_type, "proposal_id": proposal_id,
                "capacity_assertion_id": assertion_id, "required_capacity": req.get("required_capacity"),
                "amount": req.get("amount", req.get("required_capacity")),
                "passport_id": authority.get("passport_id", ""),
            }
            core._emit_proof_event("REVALIDATION_CAPACITY_VALIDATED", result["revalidation_id"], {
                "ruling": result["ruling"], "capacity_assertion_id": assertion_id,
                "cumulative_obligations": capacity["cumulative_obligations"],
            }, result["revalidated_at"])
            return JSONResponse(result)

    if request.method == "POST" and request.url.path == "/v1/execution/authorize":
        try:
            req = await request.json()
        except Exception:
            return JSONResponse({"error": "INVALID_JSON"}, status_code=400)
        rid = req.get("revalidation_id", "")
        record = VALIDATION_RECEIPTS.get(rid)
        if not record:
            return JSONResponse({
                "schema": "VGS-EXECUTION-AUTH-BLOCK-1.0",
                "revalidation_id": rid,
                "proposal_id": req.get("proposal_id", ""),
                "ruling": "REVALIDATION_RECEIPT_MISSING",
                "allowed": False,
                "reason": "Execution authorization requires a locally verified revalidation record.",
                "checked_at": _now(),
                "consequence_boundary": "NO_EXECUTION_AUTHORIZATION_ISSUED",
            }, status_code=403)
        if req.get("proposal_id") != record.get("proposal_id"):
            return JSONResponse({
                "schema": "VGS-EXECUTION-AUTH-BLOCK-1.0",
                "revalidation_id": rid,
                "proposal_id": req.get("proposal_id", ""),
                "ruling": "REVALIDATION_PROPOSAL_MISMATCH",
                "allowed": False,
                "reason": "Execution proposal does not match the proposal bound to revalidation.",
                "checked_at": _now(),
                "consequence_boundary": "NO_EXECUTION_AUTHORIZATION_ISSUED",
            }, status_code=403)
        if record:
            authority = _authority_check(record["agent_id"], record["action_type"], record.get("amount"))
            capacity = _capacity_check(record["capacity_assertion_id"], record.get("required_capacity"))
            authority_unchanged = authority.get("passport_id") == record.get("passport_id")
            if not authority["valid"] or not authority_unchanged or not capacity["valid"]:
                ts = _now()
                blocked = _signed_receipt({
                    "schema": "VGS-EXECUTION-AUTH-BLOCK-1.0", "revalidation_id": rid,
                    "proposal_id": record["proposal_id"],
                    "ruling": "AUTHORITY_INVALID" if not authority["valid"] or not authority_unchanged else capacity["ruling"],
                    "allowed": False, "authority": authority, "capacity": capacity,
                    "authority_unchanged_since_revalidation": authority_unchanged,
                    "checked_at": ts, "consequence_boundary": "NO_EXECUTION_AUTHORIZATION_ISSUED",
                })
                core._emit_proof_event("EXECUTION_AUTHORIZATION_BLOCKED", rid, {"ruling": blocked["ruling"]}, ts)
                return JSONResponse(blocked, status_code=403)
            result = await core.execution_authorize(req, x_api_key=request.headers.get("x-api-key"), authorization=request.headers.get("authorization"))
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


@app.post("/v1/delegation/passport/revoke/{agent_id}", tags=["Terry Bounded Adversarial Validation"])
async def revoke_delegation_for_validation(agent_id: str, req: dict, request: Request):
    core.require_api_key(request.headers.get("x-api-key"), request.headers.get("authorization"))
    passport = core._DELEGATION_PASSPORTS.get(agent_id)
    if not passport:
        return JSONResponse({"error": "AUTHORITY_NOT_FOUND", "agent_id": agent_id}, status_code=404)
    ts = _now()
    passport["revoked"] = True
    passport["revoked_at"] = ts
    passport["revocation_reason"] = req.get("reason", "Revoked for bounded adversarial validation")
    receipt = _signed_receipt({
        "schema": "VGS-DELEGATION-REVOCATION-1.0", "agent_id": agent_id,
        "passport_id": passport.get("passport_id", ""), "status": "REVOKED",
        "revoked_at": ts, "reason": passport["revocation_reason"],
    })
    passport["revocation_signature"] = receipt["governance_signature"]
    core._DELEGATION_PASSPORTS[agent_id] = passport
    core._emit_proof_event("DELEGATION_REVOKED", agent_id, {"passport_id": passport.get("passport_id", "")}, ts)
    return JSONResponse(receipt)
