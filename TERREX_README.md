# Terrex Resource Governance — `/v1/resource/*`

> **Terrex** is VeriSigil's AI Resource Governance layer — the world's first pre-execution AI Resource Firewall. It measures, scores, governs, and certifies the physical resources (energy, water, carbon) consumed by AI workloads before they execute.
>
> Powered by VeriSigil's existing Ed25519 signing infrastructure and RFC 3161 timestamping — every decision is cryptographically signed and stored immutably.

---

## Overview

| Module | What it does |
|---|---|
| **TerraGuard™** | Pre-execution resource firewall — ALLOW / DELAY / THROTTLE / DENY |
| **TerraScore™** | Resource Admissibility Score (0–100, A–F grade) per workload |
| **TerraLedger™** | Signed, timestamped immutable record of actual resource consumption |
| **TerraComply™** | Auto-generated EU AI Act sustainability disclosure |

---

## Authentication

All `/v1/resource/*` endpoints use the same authentication as the rest of VeriSigil.

```
x-api-key: your-api-key
```

Or as a query parameter:

```
?x_api_key=your-api-key
```

Sandbox key for testing: `vs-sandbox-demo-2026`

---

## Endpoints

### 1. TerraGuard — Pre-execution resource intercept

Evaluates an AI workload against resource budgets and sustainability thresholds **before it executes**. Returns a governance decision and a signed TerraScore.

```
POST /v1/resource/intercept
```

**Request body**

```json
{
  "workload_id": "wl-abc123",
  "model_class": "large",
  "workload_type": "inference",
  "estimated_tokens": 50000,
  "grid_region": "us_texas",
  "organisation_id": "acme-corp",
  "carbon_budget_gco2": null,
  "energy_budget_wh": null,
  "ves_envelope_id": null
}
```

**Field reference**

| Field | Type | Required | Description |
|---|---|---|---|
| `workload_id` | string | Yes | Your internal workload or request ID |
| `model_class` | string | Yes | `small` / `medium` / `large` / `frontier` |
| `workload_type` | string | Yes | `inference` / `fine_tune` / `training` / `batch` |
| `estimated_tokens` | integer | Yes | Total estimated tokens (input + output) |
| `grid_region` | string | No | See region table below. Default: `unknown` |
| `organisation_id` | string | No | Used for aggregate reporting and compliance |
| `carbon_budget_gco2` | float | No | Hard carbon limit in gCO2. Breach → DENY |
| `energy_budget_wh` | float | No | Hard energy limit in Wh. Breach → DENY |
| `ves_envelope_id` | string | No | Links decision to an existing VES evidence envelope |

**Model class reference**

| Class | Parameter range | Examples |
|---|---|---|
| `small` | < 7B | Mistral 7B, Llama 3.1 8B |
| `medium` | 7B – 70B | Llama 3.1 70B, Claude Haiku |
| `large` | 70B – 200B | Llama 3.1 405B, Claude Sonnet |
| `frontier` | > 200B or training runs | GPT-4, Claude Opus, full training |

**Grid region reference**

| Region | Carbon intensity | Water stress | Notes |
|---|---|---|---|
| `eu_nordic` | 20 gCO2/kWh | 0.3 | Best — hydro + wind |
| `eu_france` | 55 gCO2/kWh | 0.7 | Nuclear heavy |
| `eu_germany` | 380 gCO2/kWh | 0.8 | Mixed grid |
| `us_west` | 210 gCO2/kWh | 1.6 | Renewables growing |
| `us_east` | 370 gCO2/kWh | 0.9 | Gas/coal mix |
| `us_texas` | 420 gCO2/kWh | 1.8 | Gas heavy, high water stress |
| `africa_west` | 480 gCO2/kWh | 2.2 | Diesel/gas, very high water stress |
| `asia_singapore` | 430 gCO2/kWh | 1.1 | Gas |
| `asia_japan` | 490 gCO2/kWh | 0.9 | Mixed |
| `unknown` | 450 gCO2/kWh | 1.2 | Conservative default |

**Decision logic**

| Decision | Condition |
|---|---|
| `ALLOW` | Grade A, B, or C — within all budgets |
| `DELAY` | Grade F — queued for lower-carbon window (~6 hours) |
| `THROTTLE` | Grade D — reduce batch size 50% or migrate region |
| `DENY` | Budget hard breach, or Grade F in high water-stress region |

**Response — 200 OK**

```json
{
  "intercept_id": "tg-162cac4367234efa",
  "workload_id": "wl-abc123",
  "decision": "THROTTLE",
  "decision_reason": "D-grade efficiency. Reduce batch size 50% or migrate to a lower-carbon region.",
  "delay_seconds": null,
  "throttle_recommendation": "Reduce batch size by 50% OR switch to eu_nordic / eu_france.",
  "terra_score": {
    "score": 48,
    "grade": "D",
    "carbon_intensity_gco2_kwh": 420,
    "water_stress_multiplier": 1.8,
    "estimated_energy_wh": 90.0,
    "estimated_carbon_gco2": 37.8,
    "estimated_water_liters": 0.2916
  },
  "ves_envelope_id": null,
  "signature": "2zru3lzgsat4axVKdbxKDK/agUkxgdP1gYlo+...",
  "timestamp": "2026-06-06T16:12:40.896204Z",
  "public_verify_key": "lJWG0Wabt6uATPu5Upo6UEHWGXQqMyi6LMKQC0xwpY8=",
  "standard": "TerraScore-1.0"
}
```

**Live example — bad workload (Texas grid, large model)**

```bash
curl -X POST https://verisigil-api-production.up.railway.app/v1/resource/intercept \
  -H "Content-Type: application/json" \
  -H "x-api-key: vs-sandbox-demo-2026" \
  -d '{
    "workload_id": "demo-bad",
    "model_class": "large",
    "workload_type": "inference",
    "estimated_tokens": 50000,
    "grid_region": "us_texas",
    "organisation_id": "demo-org"
  }'
```

Returns: `"decision": "THROTTLE"`, `"grade": "D"`, score `48/100`

**Live example — good workload (Nordic grid, small model)**

```bash
curl -X POST https://verisigil-api-production.up.railway.app/v1/resource/intercept \
  -H "Content-Type: application/json" \
  -H "x-api-key: vs-sandbox-demo-2026" \
  -d '{
    "workload_id": "demo-good",
    "model_class": "small",
    "workload_type": "inference",
    "estimated_tokens": 5000,
    "grid_region": "eu_nordic",
    "organisation_id": "demo-org"
  }'
```

Returns: `"decision": "ALLOW"`, `"grade": "A"`, score `98/100`

---

### 2. TerraScore — Retrieve resource score

Retrieve the TerraScore for a previously intercepted workload.

```
GET /v1/resource/score/{workload_id}
```

**Response — 200 OK**

```json
{
  "workload_id": "demo-good",
  "intercept_id": "tg-6e4e91ef91f0400a",
  "terra_score": 98,
  "terra_grade": "A",
  "decision": "ALLOW",
  "estimated_carbon_gco2": 0.03,
  "estimated_energy_wh": 1.5,
  "estimated_water_liters": 0.0008,
  "grid_region": "eu_nordic",
  "timestamp": "2026-06-06T16:14:17.980347Z",
  "signature": "N7ohbDXQ6UlUxsWpXNPqqBwe7Jsy2d2GcnnZHFBZDKaCNe3...",
  "public_verify_key": "lJWG0Wabt6uATPu5Upo6UEHWGXQqMyi6LMKQC0xwpY8=",
  "standard": "TerraScore-1.0"
}
```

---

### 3. TerraLedger — Record actual resource consumption

After a workload executes, record its actual resource consumption. Creates a signed, timestamped immutable record extending the VES-1.0 Evidence Standard with resource claims.

```
POST /v1/resource/ledger/record
```

**Request body**

```json
{
  "workload_id": "wl-abc123",
  "intercept_id": "tg-162cac4367234efa",
  "ves_envelope_id": null,
  "actual_tokens": 48500,
  "actual_energy_wh": null,
  "actual_carbon_gco2": null,
  "actual_water_liters": null,
  "grid_region": "us_texas",
  "model_class": "large",
  "organisation_id": "acme-corp",
  "notes": null
}
```

> If `actual_energy_wh`, `actual_carbon_gco2`, and `actual_water_liters` are omitted, VeriSigil estimates them from `actual_tokens`, `model_class`, and `grid_region` using the TerraScore methodology.

**Response — 200 OK**

```json
{
  "ledger_id": "tl-9f3a21bc44ef7801",
  "workload_id": "wl-abc123",
  "verified_energy_wh": 87.3,
  "verified_carbon_gco2": 36.666,
  "verified_water_liters": 0.2831,
  "sustainability_claim_valid": true,
  "signature": "Ed25519-signed-base64...",
  "timestamp": "2026-06-06T16:20:11.002341Z",
  "public_verify_key": "lJWG0Wabt6uATPu5Upo6UEHWGXQqMyi6LMKQC0xwpY8=",
  "standard": "TerraLedger-1.0"
}
```

---

### 4. TerraLedger — Retrieve consumption records

```
GET /v1/resource/ledger/{workload_id}
```

**Response — 200 OK**

```json
{
  "workload_id": "wl-abc123",
  "records": [ { "...": "..." } ],
  "record_count": 1,
  "standard": "TerraLedger-1.0",
  "public_verify_key": "lJWG0Wabt6uATPu5Upo6UEHWGXQqMyi6LMKQC0xwpY8="
}
```

---

### 5. TerraComply — Generate EU AI Act sustainability disclosure

Auto-generates a signed, legally-structured EU AI Act sustainability disclosure for an organisation's AI workloads over a reporting period. References Articles 9, 40, and 53. Suitable for regulatory submission.

```
POST /v1/resource/comply/eu-ai-act
```

**Request body**

```json
{
  "organisation_id": "acme-corp",
  "report_period_start": "2026-01-01",
  "report_period_end": "2026-12-31",
  "include_ledger_detail": false,
  "framework": "eu_ai_act_2026"
}
```

**Response — 200 OK**

```json
{
  "report_id": "tc-435b62ee7bb549bd",
  "framework": "eu_ai_act_2026",
  "organisation_id": "acme-corp",
  "reporting_period": {
    "start": "2026-01-01",
    "end": "2026-12-31"
  },
  "summary": {
    "total_workloads_governed": 12,
    "total_energy_kwh": 0.0042,
    "total_carbon_kgco2": 0.0018,
    "total_water_liters": 0.31,
    "total_intercepts": 14
  },
  "governance_evidence": {
    "pre_execution_firewall": "TerraGuard-1.0 (VeriSigil Pre-Execution Gateway)",
    "resource_scoring_standard": "TerraScore-1.0",
    "ledger_standard": "TerraLedger-1.0",
    "signing_algorithm": "Ed25519 (PyNaCl)",
    "timestamp_standard": "RFC 3161",
    "decision_breakdown": {
      "ALLOW": 11,
      "DELAY": 0,
      "THROTTLE": 2,
      "DENY": 1
    },
    "grade_breakdown": {
      "A": 8,
      "B": 3,
      "C": 0,
      "D": 2,
      "F": 1
    },
    "active_governance_demonstrated": true
  },
  "compliance_status": "COMPLIANT",
  "article_references": [
    "EU AI Act Article 9 — Risk Management Systems",
    "EU AI Act Article 40 — Harmonised Standards (Sustainability Provisions)",
    "EU AI Act Article 53 — General-Purpose AI Model Transparency"
  ],
  "generated_at": "2026-06-06T16:16:10.377422Z",
  "generated_by": "VeriSigil TerraComply-1.0",
  "standard": "TerraComply-1.0",
  "signature": "/E73jai2c6ycgueUPUYsJjbyKSK4Rb6HqGk3O0AbwEaWT8...",
  "public_verify_key": "lJWG0Wabt6uATPu5Upo6UEHWGXQqMyi6LMKQC0xwpY8="
}
```

**Compliance status values**

| Status | Meaning |
|---|---|
| `COMPLIANT` | Active governance demonstrated — at least one DELAY, THROTTLE, or DENY decision recorded |
| `DISCLOSURE_ONLY` | Workloads recorded but no governance decisions made — disclosure generated but active governance not evidenced |

---

### 6. TerraComply — Retrieve a compliance report

```
GET /v1/resource/comply/{report_id}
```

Returns the previously generated compliance report by report ID.

---

### 7. Resource summary — Organisation dashboard

Aggregate resource footprint and governance statistics for an organisation.

```
GET /v1/resource/summary/{organisation_id}
```

**Response — 200 OK**

```json
{
  "organisation_id": "acme-corp",
  "total_workloads_recorded": 12,
  "total_intercepts": 14,
  "aggregate": {
    "energy_kwh": 0.0042,
    "carbon_kgco2": 0.0018,
    "water_liters": 0.31
  },
  "average_terra_score": 76,
  "standard": "TerraScore-1.0 / TerraLedger-1.0",
  "generated_at": "2026-06-06T16:25:00.000000Z",
  "public_verify_key": "lJWG0Wabt6uATPu5Upo6UEHWGXQqMyi6LMKQC0xwpY8="
}
```

---

## Signature verification

Every response from `/v1/resource/*` is signed with VeriSigil's Ed25519 key. To verify:

```python
import base64, json
import nacl.signing

public_key_b64 = "lJWG0Wabt6uATPu5Upo6UEHWGXQqMyi6LMKQC0xwpY8="
signature_b64  = "the-signature-from-response"

payload = {
    "intercept_id": "tg-162cac4367234efa",
    "workload_id":  "demo-bad",
    "decision":     "THROTTLE",
    # ... include all fields that were signed
}

verify_key = nacl.signing.VerifyKey(base64.b64decode(public_key_b64))
canonical  = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
sig_bytes  = base64.b64decode(signature_b64)

verify_key.verify(canonical, sig_bytes)  # raises if invalid
print("Signature valid")
```

---

## TerraScore methodology

TerraScore is a composite 0–100 score weighted across four dimensions:

| Dimension | Weight | What it measures |
|---|---|---|
| Carbon efficiency | 35% | Estimated gCO2 output of the workload |
| Grid carbon intensity | 30% | gCO2/kWh of the data center's grid region |
| Model efficiency | 20% | Parameter count class — smaller is more efficient |
| Water stress | 15% | Local water scarcity adjusted water consumption |

Score → Grade mapping:

| Score | Grade |
|---|---|
| 80–100 | A |
| 65–79 | B |
| 50–64 | C |
| 35–49 | D |
| 0–34 | F |

---

## Supabase tables

Three tables are created by this module:

| Table | Purpose |
|---|---|
| `terrex_intercepts` | Every TerraGuard decision — signed, indexed by workload and org |
| `terrex_ledger` | Every TerraLedger consumption record — signed, linked to VES envelopes |
| `terrex_compliance_reports` | Every TerraComply report — signed, indexed by org and period |

---

## Standards references

| Standard | Version | Applied in |
|---|---|---|
| TerraScore | 1.0 | All `/v1/resource/intercept` responses |
| TerraLedger | 1.0 | All `/v1/resource/ledger/*` responses |
| TerraComply | 1.0 | All `/v1/resource/comply/*` responses |
| VES Evidence Standard | 1.0 | Linked via `ves_envelope_id` field |
| EU AI Act | 2026 | Articles 9, 40, 53 — compliance reporting |
| RFC 3161 | — | Timestamp standard on all signed records |
| Ed25519 | — | Signing algorithm (PyNaCl) |

---

## Live base URL

```
https://verisigil-api-production.up.railway.app
```

Interactive API docs:

```
https://verisigil-api-production.up.railway.app/docs
```

Scroll to **Terrex Resource Governance** section.
