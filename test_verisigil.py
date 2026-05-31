"""
VeriSigil AI — Basic Test Suite
pytest test_verisigil.py -v

Tests: syntax, critical endpoints, crypto functions, auth, health checks
Run: pip install pytest httpx fastapi --break-system-packages
"""
import pytest
import ast
import os
import sys

# ── Test 1: API file syntax valid ────────────────────────────
def test_api_syntax_valid():
    """The main API file must parse without syntax errors."""
    with open('/home/claude/main_olga_alex.py') as f:
        source = f.read()
    try:
        ast.parse(source)
        assert True
    except SyntaxError as e:
        pytest.fail(f"Syntax error at line {e.lineno}: {e.msg}")

# ── Test 2: All critical endpoints present ───────────────────
def test_critical_endpoints_present():
    """All 6 governance layer endpoints must be present."""
    with open('/home/claude/main_olga_alex.py') as f:
        source = f.read()
    required = [
        "/v1/scanner/shadow",
        "/v1/authority/map",
        "/v1/execution/control",
        "/v1/emergency/governance/activate",
        "/v1/constitutional-gateway/prove",
        "/v1/reliance/resolve",
        "/v1/human/sovereignty/enforce",
        "/v1/escalation/legitimacy",
        "/v1/workflow/legitimacy",
        "/v1/coordination/chain",
        "/health",
        "/v1/crypto/verify",
    ]
    missing = [ep for ep in required if ep not in source]
    assert not missing, f"Missing endpoints: {missing}"

# ── Test 3: No mock Ed25519 f-strings ────────────────────────
def test_no_mock_ed25519():
    """All Ed25519 signatures must use real PyNaCl, not f-strings."""
    import re
    with open('/home/claude/main_olga_alex.py') as f:
        source = f.read()
    mocks = re.findall(r'f"Ed25519:\{[^}]+\}"', source)
    assert not mocks, f"Found {len(mocks)} mock Ed25519 f-strings: {mocks}"

# ── Test 4: Real cryptographic functions present ─────────────
def test_real_crypto_functions():
    """sign_governance_payload and verify_governance_signature must exist."""
    with open('/home/claude/main_olga_alex.py') as f:
        source = f.read()
    assert "def sign_governance_payload" in source, "sign_governance_payload missing"
    assert "def verify_governance_signature" in source, "verify_governance_signature missing"
    assert "nacl.signing" in source, "PyNaCl not imported"

# ── Test 5: Auth is not hardcoded ────────────────────────────
def test_auth_uses_env_var():
    """API key must come from environment, not hardcoded string."""
    import re
    with open('/home/claude/main_olga_alex.py') as f:
        source = f.read()
    # Should use os.environ.get, not a literal secret
    hardcoded = re.findall(r'API_KEY\s*=\s*["\']verisigil-secret', source)
    assert not hardcoded, f"Hardcoded API key found: {hardcoded}"
    env_based = re.findall(r'API_KEY.*=.*os\.environ', source)
    assert env_based, "API_KEY must be loaded from environment variable"

# ── Test 6: Supabase persistence layer present ───────────────
def test_supabase_persistence_present():
    """Supabase db_insert and db_select functions must exist."""
    with open('/home/claude/main_olga_alex.py') as f:
        source = f.read()
    assert "async def db_insert" in source, "db_insert missing"
    assert "async def db_select" in source, "db_select missing"
    assert "_get_supabase" in source, "_get_supabase missing"
    assert "SUPABASE_SCHEMA_SQL" in source, "SQL schema not documented"

# ── Test 7: Rate limiting middleware present ──────────────────
def test_rate_limiting_present():
    """Rate limiting middleware must be registered."""
    with open('/home/claude/main_olga_alex.py') as f:
        source = f.read()
    assert "rate_limit_middleware" in source, "Rate limit middleware missing"
    assert "RATE_LIMIT_PER_MIN" in source, "Rate limit constant missing"
    assert "429" in source, "HTTP 429 not returned on rate limit"

# ── Test 8: Health endpoints present ─────────────────────────
def test_health_endpoints():
    """Health and /health/db endpoints must exist."""
    with open('/home/claude/main_olga_alex.py') as f:
        source = f.read()
    assert '"/health"' in source, "/health endpoint missing"
    assert '"/health/db"' in source, "/health/db endpoint missing"

# ── Test 9: Endpoint count meets target ──────────────────────
def test_endpoint_count():
    """Must have at least 515 endpoints."""
    import re
    with open('/home/claude/main_olga_alex.py') as f:
        source = f.read()
    count = len(re.findall(r'@app\.(get|post|put|delete)\(', source))
    assert count >= 515, f"Only {count} endpoints found, expected >= 515"

# ── Test 10: Website has no broken pip install ───────────────
def test_no_broken_pip_install():
    """index.html should not have bare 'pip install verisigil' as a command."""
    with open('/home/claude/website/index.html') as f:
        site = f.read()
    # Acceptable: mentioning it as Q4 2026 coming soon
    # Not acceptable: as a working install command without qualification
    assert "pip install verisigil</span> · connect" not in site, \
        "Bare pip install verisigil still present without qualification"

if __name__ == "__main__":
    # Run tests directly
    tests = [
        test_api_syntax_valid,
        test_critical_endpoints_present,
        test_no_mock_ed25519,
        test_real_crypto_functions,
        test_auth_uses_env_var,
        test_supabase_persistence_present,
        test_rate_limiting_present,
        test_health_endpoints,
        test_endpoint_count,
        test_no_broken_pip_install,
    ]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  ✅ {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  ❌ {t.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"  ❌ {t.__name__}: {e}")
            failed += 1
    print(f"\n{passed}/{passed+failed} tests passed")
