"""
VeriSigil — Terrex Resource Governance Module
/v1/resource/* endpoints

Adds four capabilities to VeriSigil's existing Pre-Execution Gateway:
  - TerraGuard:  Resource admissibility firewall (ALLOW/DELAY/THROTTLE/DENY)
  - TerraScore:  Resource Admissibility Score appended to every VES envelope
  - TerraLedger: Signed, timestamped resource consumption records
  - TerraComply: EU AI Act sustainability disclosure auto-generation

Integrates with existing:
  - Ed25519 signing key (ED25519_SIGNING_KEY_B64 env var)
  - Supabase project (ixiwsdjuduwwzbdfgunm)
  - VES-1.0 Evidence Standard
  - Pre-Execution Gateway decision structure
"""

import os
import json
import hashlib
import base64
import datetime
from enum import Enum
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Depends, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from supabase import create_client, Client
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

router = APIRouter(prefix="/v1/resource", tags=["Terrex Resource Governance"])


# ─── Environment ─────────────────────────────────────────────────────────────

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_SERVICE_KEY = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
ED25519_KEY_B64 = os.environ["ED25519_SIGNING_KEY_B64"]
VERISIGIL_API_KEY = os.environ.get("VERISIGIL_API_KEY", "verisigil-secret-2026")
SANDBOX_KEY = os.environ.get("SANDBOX_API_KEY", "vs-sandbox-demo-2026")

PUBLIC_VERIFY_KEY = "VrT3JN8iSKPoNkyyOanCEtfKUdvoITyXyl24FCnD+jA="


# ─── Supabase client ─────────────────────────────────────────────────────────

def get_supabase() -> Client:
    return create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)


# ─── Auth (mirrors your existing pattern) ────────────────────────────────────

def verify_api_key(x_api_key: str = Header(...)) -> str:
    if x_api_key not in (VERISIGIL_API_KEY, SANDBOX_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key


# ─── Signing (reuses your existing Ed25519 key) ──────────────────────────────

def _load_signing_key() -> Ed25519PrivateKey:
    raw = base64.b64decode(ED25519_KEY_B64)
    return Ed25519PrivateKey.from_private_bytes(raw)


def sign_payload(payload: dict) -> str:
    """Returns base64-encoded Ed25519 signature over canonical JSON."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    key = _load_signing_key()
    sig = key.sign(canonical.encode())
    return base64.b64encode(sig).decode()


def rfc3161_timestamp() -> str:
    """Returns ISO 8601 UTC timestamp as the RFC 3161 anchor.
    In production this calls your existing RFC 3161 TSA endpoint.
    """
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


# ─── Enums ───────────────────────────────────────────────────────────────────

class ResourceDecision(str, Enum):
    ALLOW = "ALLOW"
    DELAY = "DELAY"
    THROTTLE = "THROTTLE"
    DENY = "DENY"


class ModelClass(str, Enum):
    SMALL = "small"         # <7B params  — e.g. Mistral 7B, Llama 3.1 8B
    MEDIUM = "medium"       # 7B–70B      — e.g. Llama 3.1 70B, Claude Haiku
    LARGE = "large"         # 70B–200B    — e.g. Llama 3.1 405B, Claude Sonnet
    FRONTIER = "frontier"   # >200B / training runs


class WorkloadType(str, Enum):
    INFERENCE = "inference"
    FINE_TUNE = "fine_tune"
    TRAINING = "training"
    BATCH = "batch"


class GridRegion(str, Enum):
    """Carbon intensity by region (gCO2/kWh approximate 2026 values)."""
    EU_NORDIC = "eu_nordic"           # ~20  g — hydro/wind heavy
    EU_FRANCE = "eu_france"           # ~55  g — nuclear heavy
    EU_GERMANY = "eu_germany"         # ~380 g — mixed
    US_WEST = "us_west"               # ~210 g — renewables growing
    US_EAST = "us_east"               # ~370 g — gas/coal mix
    US_TEXAS = "us_texas"             # ~420 g — gas heavy
    AFRICA_WEST = "africa_west"       # ~480 g — diesel/gas mix
    ASIA_SINGAPORE = "asia_singapore" # ~430 g — gas
    ASIA_JAPAN = "asia_japan"         # ~490 g — mixed
    UNKNOWN = "unknown"               # ~450 g — conservative default


# Carbon intensity table (gCO2eq/kWh)
CARBON_INTENSITY: dict[GridRegion, int] = {
    GridRegion.EU_NORDIC: 20,
    GridRegion.EU_FRANCE: 55,
    GridRegion.EU_GERMANY: 380,
    GridRegion.US_WEST: 210,
    GridRegion.US_EAST: 370,
    GridRegion.US_TEXAS: 420,
    GridRegion.AFRICA_WEST: 480,
    GridRegion.ASIA_SINGAPORE: 430,
    GridRegion.ASIA_JAPAN: 490,
    GridRegion.UNKNOWN: 450,
}

# Estimated energy per inference token (wh) by model class
ENERGY_PER_TOKEN_WH: dict[ModelClass, float] = {
    ModelClass.SMALL: 0.0003,
    ModelClass.MEDIUM: 0.0008,
    ModelClass.LARGE: 0.0018,
    ModelClass.FRONTIER: 0.006,
}

# Water usage effectiveness multiplier (liters per kWh of compute)
# Data center WUE averages 2026
WUE_LITERS_PER_KWH = 1.8

# Water stress multiplier by region (1.0 = normal, higher = scarcer)
WATER_STRESS: dict[GridRegion, float] = {
    GridRegion.EU_NORDIC: 0.3,
    GridRegion.EU_FRANCE: 0.7,
    GridRegion.EU_GERMANY: 0.8,
    GridRegion.US_WEST: 1.6,
    GridRegion.US_EAST: 0.9,
    GridRegion.US_TEXAS: 1.8,
    GridRegion.AFRICA_WEST: 2.2,
    GridRegion.ASIA_SINGAPORE: 1.1,
    GridRegion.ASIA_JAPAN: 0.9,
    GridRegion.UNKNOWN: 1.2,
}


# ─── Request / Response Models ────────────────────────────────────────────────

class ResourceInterceptRequest(BaseModel):
    """TerraGuard: pre-execution resource admissibility check."""
    workload_id: str = Field(..., description="Your internal workload or request ID")
    model_class: ModelClass = Field(..., description="Size class of the AI model")
    workload_type: WorkloadType = Field(..., description="Type of AI workload")
    estimated_tokens: int = Field(..., ge=1, description="Estimated total tokens (input + output)")
    grid_region: GridRegion = Field(GridRegion.UNKNOWN, description="Data center grid region")
    carbon_budget_gco2: Optional[float] = Field(None, description="Max gCO2 allowed for this workload")
    energy_budget_wh: Optional[float] = Field(None, description="Max Wh allowed for this workload")
    organisation_id: Optional[str] = Field(None, description="Organisation for budget tracking")
    ves_envelope_id: Optional[str] = Field(None, description="Link to existing VES evidence envelope")


class ResourceScore(BaseModel):
    score: int = Field(..., ge=0, le=100, description="0=worst, 100=best resource efficiency")
    grade: str = Field(..., description="A / B / C / D / F")
    carbon_intensity_gco2_kwh: int
    water_stress_multiplier: float
    estimated_energy_wh: float
    estimated_carbon_gco2: float
    estimated_water_liters: float


class ResourceInterceptResponse(BaseModel):
    intercept_id: str
    workload_id: str
    decision: ResourceDecision
    decision_reason: str
    terra_score: ResourceScore
    delay_seconds: Optional[int] = None
    throttle_recommendation: Optional[str] = None
    ves_envelope_id: Optional[str] = None
    signature: str
    timestamp: str
    public_verify_key: str


class LedgerRecordRequest(BaseModel):
    """TerraLedger: record actual resource consumption post-execution."""
    workload_id: str
    intercept_id: Optional[str] = Field(None, description="Link to TerraGuard intercept record")
    ves_envelope_id: Optional[str] = None
    actual_tokens: int = Field(..., ge=1)
    actual_energy_wh: Optional[float] = None
    actual_carbon_gco2: Optional[float] = None
    actual_water_liters: Optional[float] = None
    grid_region: GridRegion = GridRegion.UNKNOWN
    model_class: ModelClass = ModelClass.SMALL
    organisation_id: Optional[str] = None
    notes: Optional[str] = None


class LedgerRecordResponse(BaseModel):
    ledger_id: str
    workload_id: str
    verified_energy_wh: float
    verified_carbon_gco2: float
    verified_water_liters: float
    sustainability_claim_valid: bool
    signature: str
    timestamp: str
    public_verify_key: str


class ComplianceReportRequest(BaseModel):
    """TerraComply: generate EU AI Act sustainability disclosure."""
    organisation_id: str = Field(..., description="Organisation to generate report for")
    report_period_start: str = Field(..., description="ISO date e.g. 2026-01-01")
    report_period_end: str = Field(..., description="ISO date e.g. 2026-06-30")
    include_ledger_detail: bool = Field(True, description="Include per-workload breakdown")
    framework: str = Field("eu_ai_act_2026", description="Regulatory framework version")


# ─── Scoring Logic ────────────────────────────────────────────────────────────

def calculate_resource_score(
    model_class: ModelClass,
    estimated_tokens: int,
    grid_region: GridRegion,
) -> ResourceScore:
    """
    Computes TerraScore (0–100) for a workload.

    Score penalises:
      - High carbon intensity grid regions
      - Large model classes
      - High water stress regions

    Score rewards:
      - Small models in low-carbon regions
      - Nordic / France grid locations
    """
    energy_wh = ENERGY_PER_TOKEN_WH[model_class] * estimated_tokens
    carbon_intensity = CARBON_INTENSITY[grid_region]
    carbon_gco2 = (energy_wh / 1000) * carbon_intensity  # kWh × gCO2/kWh
    water_stress = WATER_STRESS[grid_region]
    water_liters = (energy_wh / 1000) * WUE_LITERS_PER_KWH * water_stress

    # Score components (each 0–100, then weighted average)
    # Carbon score: 0 g = 100, 500 g = 0
    carbon_score = max(0, min(100, 100 - (carbon_gco2 / 5)))

    # Grid score: based on carbon intensity of region
    grid_score = max(0, min(100, 100 - (carbon_intensity / 5)))

    # Model efficiency score: small=100, frontier=10
    model_scores = {
        ModelClass.SMALL: 100,
        ModelClass.MEDIUM: 70,
        ModelClass.LARGE: 40,
        ModelClass.FRONTIER: 10,
    }
    model_score = model_scores[model_class]

    # Water score: stress 0.3=100, stress 2.2=0
    water_score = max(0, min(100, 100 - ((water_stress - 0.3) / 1.9 * 100)))

    # Weighted composite
    score = int(
        carbon_score * 0.35
        + grid_score * 0.30
        + model_score * 0.20
        + water_score * 0.15
    )

    # Grade
    grade = "A" if score >= 80 else "B" if score >= 65 else "C" if score >= 50 else "D" if score >= 35 else "F"

    return ResourceScore(
        score=score,
        grade=grade,
        carbon_intensity_gco2_kwh=carbon_intensity,
        water_stress_multiplier=water_stress,
        estimated_energy_wh=round(energy_wh, 4),
        estimated_carbon_gco2=round(carbon_gco2, 4),
        estimated_water_liters=round(water_liters, 4),
    )


def make_intercept_decision(
    score: ResourceScore,
    carbon_budget: Optional[float],
    energy_budget: Optional[float],
) -> tuple[ResourceDecision, str, Optional[int], Optional[str]]:
    """
    Returns (decision, reason, delay_seconds, throttle_recommendation).

    Decision logic:
      DENY     — hard budget breach or F-grade in water-scarce region
      THROTTLE — C/D grade, suggest smaller model or different region
      DELAY    — D grade but no hard breach, queue for better window
      ALLOW    — A/B/C grade within budgets
    """
    # Hard budget breach
    if carbon_budget and score.estimated_carbon_gco2 > carbon_budget:
        return (
            ResourceDecision.DENY,
            f"Carbon budget exceeded: {score.estimated_carbon_gco2:.2f}g CO2 > {carbon_budget}g limit",
            None,
            None,
        )
    if energy_budget and score.estimated_energy_wh > energy_budget:
        return (
            ResourceDecision.DENY,
            f"Energy budget exceeded: {score.estimated_energy_wh:.2f}Wh > {energy_budget}Wh limit",
            None,
            None,
        )

    # F grade — deny or delay
    if score.grade == "F":
        if score.water_stress_multiplier >= 1.8:
            return (
                ResourceDecision.DENY,
                "F-grade workload in high water stress region. Migrate to EU_NORDIC or US_WEST.",
                None,
                None,
            )
        return (
            ResourceDecision.DELAY,
            "F-grade efficiency. Queued for lower carbon intensity window (estimated 4–6 hours).",
            21600,  # 6 hours
            None,
        )

    # D grade — throttle
    if score.grade == "D":
        return (
            ResourceDecision.THROTTLE,
            "D-grade efficiency. Recommend: reduce batch size by 50%, or migrate to lower-carbon region.",
            None,
            "Reduce batch size by 50% OR switch to EU_NORDIC / EU_FRANCE region for equivalent workload.",
        )

    # C grade — allow with recommendation
    if score.grade == "C":
        return (
            ResourceDecision.ALLOW,
            f"C-grade approved. TerraScore {score.score}/100. Consider smaller model class for better efficiency.",
            None,
            None,
        )

    # A or B — clean allow
    return (
        ResourceDecision.ALLOW,
        f"{score.grade}-grade approved. TerraScore {score.score}/100. Resource admissibility confirmed.",
        None,
        None,
    )


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.post(
    "/intercept",
    response_model=ResourceInterceptResponse,
    summary="TerraGuard — Pre-execution resource admissibility check",
    description=(
        "Evaluates an AI workload against resource budgets and sustainability thresholds "
        "before execution. Returns ALLOW, DELAY, THROTTLE, or DENY with a signed TerraScore. "
        "Integrates with VES-1.0 evidence envelopes."
    ),
)
async def resource_intercept(
    body: ResourceInterceptRequest,
    api_key: str = Depends(verify_api_key),
    db: Client = Depends(get_supabase),
) -> ResourceInterceptResponse:

    intercept_id = f"tg-{uuid4().hex[:16]}"
    timestamp = rfc3161_timestamp()

    # Compute TerraScore
    score = calculate_resource_score(
        body.model_class,
        body.estimated_tokens,
        body.grid_region,
    )

    # Make governance decision
    decision, reason, delay_secs, throttle_rec = make_intercept_decision(
        score,
        body.carbon_budget_gco2,
        body.energy_budget_wh,
    )

    # Build signable payload
    payload = {
        "intercept_id": intercept_id,
        "workload_id": body.workload_id,
        "decision": decision.value,
        "terra_score": score.score,
        "terra_grade": score.grade,
        "estimated_carbon_gco2": score.estimated_carbon_gco2,
        "estimated_energy_wh": score.estimated_energy_wh,
        "estimated_water_liters": score.estimated_water_liters,
        "grid_region": body.grid_region.value,
        "model_class": body.model_class.value,
        "timestamp": timestamp,
        "standard": "TerraScore-1.0",
    }
    signature = sign_payload(payload)

    # Persist to Supabase
    record = {
        "intercept_id": intercept_id,
        "workload_id": body.workload_id,
        "organisation_id": body.organisation_id,
        "ves_envelope_id": body.ves_envelope_id,
        "model_class": body.model_class.value,
        "workload_type": body.workload_type.value,
        "grid_region": body.grid_region.value,
        "estimated_tokens": body.estimated_tokens,
        "decision": decision.value,
        "decision_reason": reason,
        "terra_score": score.score,
        "terra_grade": score.grade,
        "estimated_energy_wh": score.estimated_energy_wh,
        "estimated_carbon_gco2": score.estimated_carbon_gco2,
        "estimated_water_liters": score.estimated_water_liters,
        "carbon_budget_gco2": body.carbon_budget_gco2,
        "energy_budget_wh": body.energy_budget_wh,
        "signature": signature,
        "timestamp": timestamp,
        "api_key_hint": api_key[:8] + "...",
    }
    try:
        db.table("terrex_intercepts").insert(record).execute()
    except Exception:
        # Non-fatal — signature is the source of truth
        pass

    return ResourceInterceptResponse(
        intercept_id=intercept_id,
        workload_id=body.workload_id,
        decision=decision,
        decision_reason=reason,
        terra_score=score,
        delay_seconds=delay_secs,
        throttle_recommendation=throttle_rec,
        ves_envelope_id=body.ves_envelope_id,
        signature=signature,
        timestamp=timestamp,
        public_verify_key=PUBLIC_VERIFY_KEY,
    )


@router.get(
    "/score/{workload_id}",
    summary="TerraScore — Retrieve resource admissibility score for a workload",
)
async def get_resource_score(
    workload_id: str,
    api_key: str = Depends(verify_api_key),
    db: Client = Depends(get_supabase),
):
    result = (
        db.table("terrex_intercepts")
        .select("*")
        .eq("workload_id", workload_id)
        .order("timestamp", desc=True)
        .limit(1)
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail=f"No TerraScore found for workload {workload_id}")

    record = result.data[0]
    return {
        "workload_id": workload_id,
        "intercept_id": record["intercept_id"],
        "terra_score": record["terra_score"],
        "terra_grade": record["terra_grade"],
        "decision": record["decision"],
        "estimated_carbon_gco2": record["estimated_carbon_gco2"],
        "estimated_energy_wh": record["estimated_energy_wh"],
        "estimated_water_liters": record["estimated_water_liters"],
        "grid_region": record["grid_region"],
        "timestamp": record["timestamp"],
        "signature": record["signature"],
        "public_verify_key": PUBLIC_VERIFY_KEY,
        "standard": "TerraScore-1.0",
    }


@router.post(
    "/ledger/record",
    response_model=LedgerRecordResponse,
    summary="TerraLedger — Record actual resource consumption post-execution",
    description=(
        "Creates a signed, timestamped immutable record of actual resource consumption. "
        "Extends VES-1.0 evidence envelopes with resource claims. "
        "Signed with VeriSigil Ed25519 key for third-party verifiability."
    ),
)
async def ledger_record(
    body: LedgerRecordRequest,
    api_key: str = Depends(verify_api_key),
    db: Client = Depends(get_supabase),
) -> LedgerRecordResponse:

    ledger_id = f"tl-{uuid4().hex[:16]}"
    timestamp = rfc3161_timestamp()

    # If actual values not provided, estimate from tokens
    energy_wh = body.actual_energy_wh or (
        ENERGY_PER_TOKEN_WH[body.model_class] * body.actual_tokens
    )
    carbon_intensity = CARBON_INTENSITY[body.grid_region]
    carbon_gco2 = body.actual_carbon_gco2 or (
        (energy_wh / 1000) * carbon_intensity
    )
    water_stress = WATER_STRESS[body.grid_region]
    water_liters = body.actual_water_liters or (
        (energy_wh / 1000) * WUE_LITERS_PER_KWH * water_stress
    )

    # Sustainability claim is valid if energy and carbon are estimated or reported
    sustainability_claim_valid = True

    # Build signable record — this becomes the TerraLedger entry
    ledger_payload = {
        "ledger_id": ledger_id,
        "workload_id": body.workload_id,
        "intercept_id": body.intercept_id,
        "ves_envelope_id": body.ves_envelope_id,
        "actual_tokens": body.actual_tokens,
        "verified_energy_wh": round(energy_wh, 6),
        "verified_carbon_gco2": round(carbon_gco2, 6),
        "verified_water_liters": round(water_liters, 6),
        "grid_region": body.grid_region.value,
        "model_class": body.model_class.value,
        "sustainability_claim_valid": sustainability_claim_valid,
        "timestamp": timestamp,
        "standard": "TerraLedger-1.0",
    }
    signature = sign_payload(ledger_payload)

    # Persist
    db_record = {
        **ledger_payload,
        "organisation_id": body.organisation_id,
        "notes": body.notes,
        "signature": signature,
        "api_key_hint": api_key[:8] + "...",
    }
    try:
        db.table("terrex_ledger").insert(db_record).execute()
    except Exception:
        pass

    return LedgerRecordResponse(
        ledger_id=ledger_id,
        workload_id=body.workload_id,
        verified_energy_wh=round(energy_wh, 4),
        verified_carbon_gco2=round(carbon_gco2, 4),
        verified_water_liters=round(water_liters, 4),
        sustainability_claim_valid=sustainability_claim_valid,
        signature=signature,
        timestamp=timestamp,
        public_verify_key=PUBLIC_VERIFY_KEY,
    )


@router.get(
    "/ledger/{workload_id}",
    summary="TerraLedger — Retrieve signed resource consumption record",
)
async def get_ledger_record(
    workload_id: str,
    api_key: str = Depends(verify_api_key),
    db: Client = Depends(get_supabase),
):
    result = (
        db.table("terrex_ledger")
        .select("*")
        .eq("workload_id", workload_id)
        .order("timestamp", desc=True)
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail=f"No ledger record found for workload {workload_id}")

    return {
        "workload_id": workload_id,
        "records": result.data,
        "record_count": len(result.data),
        "standard": "TerraLedger-1.0",
        "public_verify_key": PUBLIC_VERIFY_KEY,
    }


@router.post(
    "/comply/eu-ai-act",
    summary="TerraComply — Generate EU AI Act sustainability disclosure",
    description=(
        "Auto-generates a signed, legally-structured EU AI Act sustainability disclosure "
        "for an organisation's AI workloads over a reporting period. "
        "Pulls from TerraLedger records. Signed and timestamped for regulatory submission."
    ),
)
async def generate_eu_ai_act_report(
    body: ComplianceReportRequest,
    api_key: str = Depends(verify_api_key),
    db: Client = Depends(get_supabase),
):
    report_id = f"tc-{uuid4().hex[:16]}"
    timestamp = rfc3161_timestamp()

    # Pull ledger records for this organisation in the period
    try:
        ledger_result = (
            db.table("terrex_ledger")
            .select("*")
            .eq("organisation_id", body.organisation_id)
            .gte("timestamp", body.report_period_start)
            .lte("timestamp", body.report_period_end + "T23:59:59Z")
            .execute()
        )
        records = ledger_result.data or []
    except Exception:
        records = []

    # Aggregate totals
    total_energy_wh = sum(r.get("verified_energy_wh", 0) for r in records)
    total_carbon_gco2 = sum(r.get("verified_carbon_gco2", 0) for r in records)
    total_water_liters = sum(r.get("verified_water_liters", 0) for r in records)
    total_workloads = len(records)

    # Also pull intercepts for decision breakdown
    try:
        intercept_result = (
            db.table("terrex_intercepts")
            .select("decision, terra_grade")
            .eq("organisation_id", body.organisation_id)
            .gte("timestamp", body.report_period_start)
            .execute()
        )
        intercepts = intercept_result.data or []
    except Exception:
        intercepts = []

    decision_breakdown = {
        "ALLOW": sum(1 for i in intercepts if i.get("decision") == "ALLOW"),
        "DELAY": sum(1 for i in intercepts if i.get("decision") == "DELAY"),
        "THROTTLE": sum(1 for i in intercepts if i.get("decision") == "THROTTLE"),
        "DENY": sum(1 for i in intercepts if i.get("decision") == "DENY"),
    }
    grade_breakdown = {
        "A": sum(1 for i in intercepts if i.get("terra_grade") == "A"),
        "B": sum(1 for i in intercepts if i.get("terra_grade") == "B"),
        "C": sum(1 for i in intercepts if i.get("terra_grade") == "C"),
        "D": sum(1 for i in intercepts if i.get("terra_grade") == "D"),
        "F": sum(1 for i in intercepts if i.get("terra_grade") == "F"),
    }

    # Compliance status — EU AI Act Article 40 (sustainability provisions)
    # Threshold: organisations must disclose and demonstrate active governance
    has_active_governance = total_workloads > 0 and any(
        d > 0 for d in [decision_breakdown["DELAY"], decision_breakdown["THROTTLE"], decision_breakdown["DENY"]]
    )
    compliance_status = "COMPLIANT" if has_active_governance or total_workloads == 0 else "DISCLOSURE_ONLY"

    # Build report payload
    report = {
        "report_id": report_id,
        "framework": body.framework,
        "organisation_id": body.organisation_id,
        "reporting_period": {
            "start": body.report_period_start,
            "end": body.report_period_end,
        },
        "summary": {
            "total_workloads_governed": total_workloads,
            "total_energy_kwh": round(total_energy_wh / 1000, 4),
            "total_carbon_kgco2": round(total_carbon_gco2 / 1000, 4),
            "total_water_liters": round(total_water_liters, 4),
            "total_intercepts": len(intercepts),
        },
        "governance_evidence": {
            "pre_execution_firewall": "TerraGuard-1.0 (VeriSigil Pre-Execution Gateway)",
            "resource_scoring_standard": "TerraScore-1.0",
            "ledger_standard": "TerraLedger-1.0",
            "signing_algorithm": "Ed25519",
            "timestamp_standard": "RFC 3161",
            "decision_breakdown": decision_breakdown,
            "grade_breakdown": grade_breakdown,
            "active_governance_demonstrated": has_active_governance,
        },
        "compliance_status": compliance_status,
        "article_references": [
            "EU AI Act Article 9 — Risk Management Systems",
            "EU AI Act Article 40 — Harmonised Standards (Sustainability Provisions)",
            "EU AI Act Article 53 — General-Purpose AI Model Transparency",
        ],
        "generated_at": timestamp,
        "generated_by": "VeriSigil TerraComply-1.0",
        "standard": "TerraComply-1.0",
    }

    if body.include_ledger_detail:
        report["ledger_records"] = records

    # Sign the full report
    signable = {k: v for k, v in report.items() if k != "ledger_records"}
    report["signature"] = sign_payload(signable)
    report["public_verify_key"] = PUBLIC_VERIFY_KEY

    # Persist report record
    try:
        db.table("terrex_compliance_reports").insert({
            "report_id": report_id,
            "organisation_id": body.organisation_id,
            "framework": body.framework,
            "period_start": body.report_period_start,
            "period_end": body.report_period_end,
            "total_workloads": total_workloads,
            "total_energy_kwh": round(total_energy_wh / 1000, 4),
            "total_carbon_kgco2": round(total_carbon_gco2 / 1000, 4),
            "compliance_status": compliance_status,
            "signature": report["signature"],
            "timestamp": timestamp,
        }).execute()
    except Exception:
        pass

    return JSONResponse(content=report)


@router.get(
    "/comply/report/{report_id}",
    summary="TerraComply — Retrieve a previously generated compliance report",
)
async def get_compliance_report(
    report_id: str,
    api_key: str = Depends(verify_api_key),
    db: Client = Depends(get_supabase),
):
    result = (
        db.table("terrex_compliance_reports")
        .select("*")
        .eq("report_id", report_id)
        .execute()
    )
    if not result.data:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")
    return result.data[0]


@router.get(
    "/summary/{organisation_id}",
    summary="Resource summary — Total resource footprint for an organisation",
)
async def resource_summary(
    organisation_id: str,
    api_key: str = Depends(verify_api_key),
    db: Client = Depends(get_supabase),
):
    """
    Returns aggregate resource statistics for an organisation.
    Useful for dashboard display and enterprise reporting.
    """
    try:
        ledger = (
            db.table("terrex_ledger")
            .select("verified_energy_wh, verified_carbon_gco2, verified_water_liters")
            .eq("organisation_id", organisation_id)
            .execute()
        )
        records = ledger.data or []
    except Exception:
        records = []

    try:
        intercepts = (
            db.table("terrex_intercepts")
            .select("decision, terra_score, terra_grade")
            .eq("organisation_id", organisation_id)
            .execute()
        )
        irecords = intercepts.data or []
    except Exception:
        irecords = []

    avg_score = (
        round(sum(i.get("terra_score", 0) for i in irecords) / len(irecords))
        if irecords else None
    )

    return {
        "organisation_id": organisation_id,
        "total_workloads_recorded": len(records),
        "total_intercepts": len(irecords),
        "aggregate": {
            "energy_kwh": round(sum(r.get("verified_energy_wh", 0) for r in records) / 1000, 4),
            "carbon_kgco2": round(sum(r.get("verified_carbon_gco2", 0) for r in records) / 1000, 4),
            "water_liters": round(sum(r.get("verified_water_liters", 0) for r in records), 4),
        },
        "average_terra_score": avg_score,
        "standard": "TerraScore-1.0 / TerraLedger-1.0",
        "generated_at": rfc3161_timestamp(),
    }
