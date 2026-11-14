# VeriSigil — Local Reproduction Quickstart

This guide runs the bounded tests with synthetic values. It does not call production, use production credentials, or prove production readiness.

## 1. Select the evaluation revision

The current staging evaluation candidate is:

- Branch: security/terry-fail-closed-execution-20261113
- Commit: dfa626d309cf397f4e861a3449f258dcb6b5fdf5

~~~bash
git clone https://github.com/raheem-verisigil/verisigil-api.git
cd verisigil-api
git fetch origin security/terry-fail-closed-execution-20261113
git checkout dfa626d309cf397f4e861a3449f258dcb6b5fdf5
~~~

## 2. Create an isolated Python environment

Python 3.12 is the reference CI version.

~~~bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
~~~

## 3. Set synthetic test-only values

These values are deliberately non-production placeholders and exist only in the current shell process.

~~~bash
export DEPLOY_ENV=test
export SUPABASE_URL=http://127.0.0.1:1
export SUPABASE_KEY=verisigil-test-only-not-a-credential
export VERISIGIL_API_KEY=verisigil-test-api-key-only
export SIGN_SECRET=verisigil-test-signing-secret-not-for-deployment
~~~

Do not replace these with production values. The focused tests are designed to use synthetic fixtures; the Terry test currently substitutes a fake in-memory receipt store.

## 4. Run the checks

~~~bash
python -m compileall -q .
python -m unittest tests.test_proof_verification -v
python -m unittest tests.test_execution_authorization_fail_closed -v
python -m unittest tests.test_terry_validation -v
python -m unittest discover -s tests -v
~~~

Retain the full terminal output, Python version, exact commit SHA, and exit code. A command being available or a test file existing is not a passing result.

## 5. Understand what the tests establish

The Terry scenario exercises synthetic authority revocation, contradictory capacity evidence, restoration, signed receipt verification, and replay refusal. Its receipt adapter is mocked in-memory. It does not prove live Supabase REST persistence, process-restart recovery, multi-instance concurrency, source authenticity of capacity data, or downstream actuator enforcement.

For the complete status and remaining gates, read [EVIDENCE_BASELINE.md](EVIDENCE_BASELINE.md).

## 6. Safety boundary

- Never run this suite against production.
- Never paste API keys, signing secrets, database credentials, or customer data into a public issue.
- Do not treat a passing local suite as proof of production-wide enforcement.
- Do not claim a real payment or external consequence occurred unless the corresponding external system provides independently checkable evidence.
