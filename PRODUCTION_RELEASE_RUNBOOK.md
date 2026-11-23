# VeriSigil Cryptographic Passport — Production Release Runbook

**Status: staging acceptance substantially advanced; production release remains blocked pending the explicit controls in Section 7.**

This runbook governs the Cryptographic Passport, tenant registry, bounded delegation, runtime authority and legacy durable validation-receipt path. It is an evidence ledger and operational procedure, not a declaration that the service is production-ready or independently security-certified.

## 1. Environment separation

Maintain three distinct environments:

- **Local/test:** synthetic credentials only; CI uses test signing material and isolated/mocked dependencies.
- **Staging:** isolated Supabase project `VeriSigil-Isolated-Staging` and Railway service `verisigil-passport-staging-api`.
- **Production:** separately approved Supabase project, Railway service and issuer-signing key set. Never reuse staging database credentials, API keys or signing secrets.

The production service has not been changed by the current readiness work. Staging acceptance does not authorize production promotion.

## 2. Required API environment variables

| Variable | Purpose | Handling |
|---|---|---|
| `SUPABASE_URL` | Environment-specific Supabase project URL | Server environment |
| `SUPABASE_ANON_KEY` | Publishable key for Supabase Auth user flows where required | Public key; keep server configuration consistent |
| `SUPABASE_SERVICE_KEY` | Server-side Supabase secret API key for PostgREST/RPC ledger operations | Secret manager only; never browser, Git, logs or chat |
| `SIGN_SECRET` | Existing VeriSigil issuer-signing material | Secret manager only; separate per environment and backed up securely |
| `VERISIGIL_API_KEY` | Legacy API compatibility credential for existing core routes | Secret manager only; rotate independently |
| `DEPLOY_ENV` | Runtime environment marker | Set to `staging` or `production` |
| `PORT` | Railway listener port | Railway-provided/configured |

The isolated staging service has a `SUPABASE_SERVICE_KEY` variable. The durable receipt and Passport persistence paths now use `SUPABASE_SERVICE_KEY` (or the legacy `SUPABASE_SERVICE_ROLE_KEY` fallback), never the public `SUPABASE_KEY`. Modern `sb_secret_` keys are sent as `apikey` credentials without incorrectly treating them as JWT Bearer tokens. Do not print or copy any secret value into GitHub, logs, browser code or chat.

Before production promotion, verify the production service's exact variable names against the deployed code. The read-only Railway inventory showed both `SUPABASE_ANON_KEY_NEW` and `SUPABASE_KEY`; do not assume the former is consumed by the application without confirming the runtime's actual lookup path.

## 3. Database release

1. Confirm the target project is the approved environment and reports healthy.
2. Apply ordered, reviewed migrations and verify migration history.
3. Verify every Passport identity, tenant, delegation, authority-commitment and receipt table has RLS enabled.
4. Verify `anon` and `authenticated` have no direct ledger table privileges.
5. Verify only `service_role` can execute privileged `vgs_*` functions.
6. Verify each SECURITY DEFINER function has a fixed safe search path.
7. Run Supabase security, health and performance advisors. Resolve all security findings and unindexed foreign keys. Unused indexes on a low-traffic/empty staging database are informational; review them only after representative traffic exists.
8. Take a backup and perform a restore rehearsal before production traffic.

Never apply a staging migration to production without reviewing its SQL, migration order, backup and rollback implications.

## 4. Auth and tenant bootstrap

1. Configure Supabase Auth site URL and exact redirect allowlist for the intended website origins.
2. Create dedicated test accounts through the approved staging Auth flow.
3. Complete email confirmation where required, then sign in.
4. Create the first tenant through authenticated `POST /v1/agent-identity/tenants`.
5. Confirm tenant and owner membership are committed together.
6. Confirm an unauthenticated request and an unrelated user cannot access the tenant.
7. Do not insert membership rows using client-supplied user IDs.

## 5. Mandatory staging acceptance tests

Use synthetic data and two independent staging Auth users.

### Live acceptance already passed

The live authenticated staging suite has passed on the readiness branch, including:

- Tenant creation, owner membership and read-after-write persistence.
- Unrelated-user tenant enumeration denial and cross-tenant selection denial.
- API-key scope enforcement, unsupported-scope rejection, anti-escalation and revocation.
- Ed25519 proof-of-possession registration and signed Passport verification.
- Single-use registration challenge and key-rotation challenge replay rejection.
- Proof-bound key rotation, Passport version increment and old-key rejection for new actions.
- Delegation constrained by grantor capabilities.
- Exact-parameter signed runtime-authority evaluation.
- Single-use authority commitment consumption, verifiable receipt and replay rejection.
- Revocation of a delegation before consumption invalidating pending authority.
- Agent revocation cascading to active cryptographic keys.

The API explicitly reports `actuator_invoked: false` in these tests. The test proves authority evaluation/consumption, not that a customer's external actuator executed.

The Python regression suite passed **29 tests**. Pinned dependency installation, compile checks and the `pip-audit` CI step also passed on the dependency-pinning change.

### Database evidence already verified

- Eight staging migrations are recorded, including `20261123210926_durable_validation_receipts`.
- The `vgs_validation_receipts` table has RLS enabled and one deny-all client policy.
- `anon` and `authenticated` have no table SELECT or consume-RPC EXECUTE privileges; `service_role` has the required grants.
- A database probe verified first consume returns the stored record, replay returns NULL, proposal mismatch returns NULL, and the probe row is deleted.
- Staging security and health advisors have no database lint findings except the Auth leaked-password warning described below. Performance advisor currently reports ten unused-index informational findings.

### Still-required tests before production

- Exercise the legacy revalidation-to-execution receipt flow end to end through the live application, not only its database RPC probe and credential unit tests.
- Two simultaneous consume attempts: exactly one can succeed.
- Process restart and multi-instance tests against the same database.
- Challenge expiry and wrong-key rejection under adversarial conditions.
- Expired/revoked Auth sessions, malformed JWTs, issuer/audience mismatch and tenant spoofing.
- CORS preflight from approved origins and rejection of unknown origins.
- Rate limiting and abuse controls for Auth, challenges and API-key creation.
- Backup restore and recovery of signing material.
- Customer actuator adapter tests in a controlled pilot.

A passing unit test is not a substitute for live integration tests.

## 6. Customer actuator contract

The API evaluates and consumes an authorization commitment; it does not invoke a customer's payment, deployment or other actuator.

A customer adapter must:
1. Verify the signed decision and action digest.
2. Call consume immediately before the protected action.
3. Execute only if consume returns the expected commitment, tenant, agent, key, action digest and valid signed receipt.
4. Bind the actuator request to the exact evaluated parameters.
5. Fail closed on timeout, malformed response, missing receipt, replay or signature failure.
6. Record the actuator's own outcome separately. A VeriSigil authority receipt is not proof that the external action succeeded.

Do not describe this integration as universal non-bypass enforcement until each supported actuator adapter has its own adversarial test evidence.

## 7. Production go/no-go

Production release remains blocked until all of the following are evidenced:

- Dedicated production database and Railway service, not the staging project.
- Production service source connected to an approved immutable repository commit/branch and a controlled promotion process.
- Environment-specific Supabase secret key and issuer-signing material, verified by variable name and runtime lookup (never by exposing values).
- All production database migrations reviewed, applied and verified.
- Full live staging acceptance, including the outstanding legacy receipt, concurrency and restart tests.
- Supabase Auth leaked-password protection enabled where supported by the project's plan; the current staging Auth advisor reports it is disabled.
- Independent security review/penetration test findings closed or formally accepted.
- Rate limiting, abuse monitoring, alerting and incident response configured.
- Backups and restore rehearsal verified.
- Key rotation, revocation and incident runbooks rehearsed.
- Production domain, TLS, CORS and security headers checked.
- Customer actuator adapter tested in a controlled pilot.
- Website copy and OpenAPI accurately reflect deployed capabilities.
- Named release owner and rollback approval recorded.

## 8. Deployment and rollback

1. Deploy the approved immutable API commit to isolated staging.
2. Run dependency audit, unit/security regression, live Passport acceptance and staging runtime gates.
3. Record commit SHA, migration versions, environment variable names (never values), test results and reviewer.
4. Confirm production source linkage, configuration parity, backup and rollback before any production deployment.
5. Deploy production only after a separate go/no-go approval.
6. Monitor health, error rates, authentication failures, denied actions, database latency and receipt persistence.
7. If a release fails, roll the API service back to the last known-good immutable deployment and keep the database fail-closed. Prefer forward-only corrective migrations; do not casually drop identity ledger tables or reverse applied production migrations.
8. Reconcile consumed commitments or incomplete receipts before re-enabling actuator integrations.

## 9. Current evidence and open issues

- **Staging Supabase:** project `lgyxxxvlxlynylhjxbxb`; eight migrations recorded; PostgreSQL health advisor clean.
- **Staging Railway:** isolated service `verisigil-passport-staging-api`; the pinned-dependency deployment `c7544786-d468-4fa1-a73f-4716b7c1eb9d` succeeded, followed by a successful runbook-only redeploy `3573243a-7f6a-48c4-ba75-8d78c151b585`. The active staging service is on the readiness branch with the pinned dependency set.
- **CI:** 29 Python tests pass; live health/OpenAPI/fail-closed auth gates pass; live Passport tenant, identity, delegation and authority acceptance passes; dependency pins and `pip-audit` gate pass.
- **Staging HTTP:** the latest inspected one-hour window showed 529 requests, zero 5xx responses; expected 4xx denials are included in that total.
- **Test cleanup:** acceptance tests revoke their temporary agents, keys and delegations. The inspected database had no active test agents, active agent keys, active delegations, active tenant API keys, unconsumed authorized commitments or durable receipt rows.
- **Durable legacy receipt path:** table/RLS/grants/RPC are deployed and the SQL single-use probe passed. The complete legacy API revalidation-to-execution path still needs a live end-to-end test.
- **Supabase Auth:** leaked-password protection is disabled. Enable it in Supabase Dashboard → Authentication → Sign In / Providers → Email → Prevent use of leaked passwords, if available on the project's plan. Supabase documents that this feature is available on Pro and above: https://supabase.com/docs/guides/auth/password-security
- **Performance advisor:** ten unused indexes are informational; do not drop them without representative traffic analysis.
- **Production Railway:** existing `verisigil-api` deployment remains on the older 2026-11-14 release. The last inspected 24-hour window showed 111 requests and zero 5xx responses. Its service configuration did not expose a repository/branch source association, so controlled source linkage must be established and verified before promotion.
- **Runtime capability:** current staging logs report Ed25519 only; Dilithium-3 is unavailable and Z3 formal proofs are disabled. Do not claim post-quantum Passport signatures or active Z3 proof verification.
- **OpenAPI:** FastAPI still reports duplicate operation-ID warnings for legacy onboarding/authority routes. These do not currently prevent OpenAPI from returning HTTP 200, but should be corrected before SDK generation and external integration contracts are frozen.
- **Production:** no production service, production database or production signing key was changed by this readiness work.

**Release state: NOT APPROVED FOR PRODUCTION until every go/no-go item above is evidenced and a separate production approval is recorded.**
