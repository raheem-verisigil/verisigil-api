"""
VeriSigil staging CI health check.

This script is deliberately fail-closed: missing dependencies/configuration,
unreachable endpoints, non-200 responses, redirects, or unexpected payloads
must fail the check. It never falls back to production.
"""
from __future__ import annotations

import os
import sys
from urllib.parse import urlparse

try:
    import httpx
except ImportError as exc:  # A skipped dependency must never produce green CI.
    print(f"FAIL: required dependency httpx is unavailable: {exc}", file=sys.stderr)
    raise SystemExit(2)


def _configuration() -> tuple[str, str]:
    base = os.environ.get("VERISIGIL_URL", "").strip().rstrip("/")
    key = os.environ.get("VERISIGIL_KEY", "").strip()
    test_env = os.environ.get("VERISIGIL_TEST_ENV", "").strip().lower()
    if test_env != "staging" or not base or not key:
        raise ValueError(
            "Require VERISIGIL_TEST_ENV=staging, VERISIGIL_URL and VERISIGIL_KEY."
        )

    target = urlparse(base)
    host = (target.hostname or "").lower()
    if (
        target.scheme != "https"
        or not host
        or target.username
        or target.password
        or target.query
        or target.fragment
        or target.path not in ("", "/")
    ):
        raise ValueError("VERISIGIL_URL must be a root HTTPS URL without credentials, path, query or fragment.")
    if "production" in host or host.startswith("prod.") or ".prod." in host:
        raise ValueError("Production targets are forbidden.")
    if not ("staging" in host or "stage" in host or "test" in host):
        raise ValueError("Target hostname must be explicitly labelled staging, stage or test.")
    return base, key


def _request(client: httpx.Client, label: str, method: str, path: str,
             headers: dict[str, str] | None = None, payload: dict | None = None) -> httpx.Response:
    try:
        response = client.request(method, path, headers=headers, json=payload)
    except httpx.HTTPError as exc:
        raise RuntimeError(f"{label}: request failed: {type(exc).__name__}") from exc
    if response.is_redirect:
        raise RuntimeError(f"{label}: redirects are not accepted (HTTP {response.status_code}).")
    if response.status_code != 200:
        raise RuntimeError(f"{label}: expected HTTP 200, received {response.status_code}.")
    return response


def run() -> int:
    try:
        base, key = _configuration()
    except ValueError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2

    api_headers = {"x-api-key": key, "Content-Type": "application/json"}
    checks: list[str] = []
    failures: list[str] = []

    print("VeriSigil staging CI health check")
    print(f"Target host: {urlparse(base).hostname}")
    print()

    with httpx.Client(base_url=base, timeout=20.0, follow_redirects=False) as client:
        probes = [
            ("health", "GET", "/health", None, None),
            ("liveness", "GET", "/liveness", None, None),
            ("readiness", "GET", "/readiness", None, None),
            ("fail-safe", "GET", "/v1/governance/failsafe", api_headers, None),
            ("sovereignty", "GET", "/v1/human/sovereignty/status", api_headers, None),
            (
                "HAL authority",
                "POST",
                "/v1/human/authority/check",
                api_headers,
                {"agent_id": "ci", "action_type": "fire_employee", "domain": "hr", "consequence": "CRITICAL"},
            ),
            ("governance pulse", "GET", "/v1/diagnostics/pulse", api_headers, None),
            ("database status", "GET", "/v1/db/status", api_headers, None),
        ]

        for label, method, path, headers, payload in probes:
            try:
                response = _request(client, label, method, path, headers, payload)
                body = response.json() if response.content else {}
                if label == "fail-safe" and body.get("failsafe_behavior") != "DENY":
                    raise RuntimeError("fail-safe: expected failsafe_behavior=DENY.")
                if label == "sovereignty" and body.get("sovereignty_posture") != "HUMAN_SOVEREIGN":
                    raise RuntimeError("sovereignty: expected HUMAN_SOVEREIGN posture.")
                if label == "HAL authority" and body.get("human_required") is not True:
                    raise RuntimeError("HAL authority: expected human_required=true.")
                if label in ("governance pulse", "database status") and not isinstance(body, dict):
                    raise RuntimeError(f"{label}: expected a JSON object.")
                checks.append(label)
                print(f"PASS {label} — HTTP 200")
            except (RuntimeError, ValueError) as exc:
                failures.append(label)
                print(f"FAIL {exc}", file=sys.stderr)

    print()
    print(f"Passed: {len(checks)}")
    print(f"Failed: {len(failures)}")
    if failures:
        print("FAILED CHECKS: " + ", ".join(failures), file=sys.stderr)
        return 1
    print("All configured staging health checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
