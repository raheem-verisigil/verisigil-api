# VeriSigil Cryptographic Passport — Production Release Runbook

**Status: staging deployed; production release blocked pending secret provisioning and live end-to-end evidence.**

This runbook governs the Cryptographic Passport, tenant registry, bounded delegation and runtime-authority endpoints. It is not a declaration of production readiness or a substitute for an independent security assessment.

## 1. Environment separation

Maintain three distinct environments:

- **Local/test:** synthetic credentials only; CI uses mocked persistence and test signing material.
- **Staging:** isolated Supabase project `VeriSigil-Isolated-Staging` and Railway service `verisigil-passport-staging-api`.
- **Production:** a separately approved Supabase project, Railway service and signing-key set. Do not reuse staging database credentials, API keys or signing secrets.

Production is not activated by this runbook. The existing production API and website remain unchanged until a separate release approval.

## 2. Required API environment variables

| Variable | Purpose | Handling |
|---|---|---|
| `SUPABASE_URL` | Environment-specific Supabase project URL | Server environment |
| `SUPABASE_ANON_KEY` | Publishable key used with Supabase Auth user verification | May be public, but keep server configuration consistent |
| `SUPABASE_SERVICE_KEY` | Server-side Supabase secret API key used for PostgREST/RPC ledger operations | Secret manager only; never browser, Git, logs or chat |
| `SIGN_SECRET` | Existing VeriSigil issuer-signing material | Secret manager only; separate per environment and backed up securely |
| `VERISIGIL_API_KEY` | Legacy API compatibility credential for existing core routes | Secret manager only; rotate independently |
| `DEPLOY_ENV` | Runtime environment marker | Set to `staging` or `production` |
| `PORT` | Railway listener port | Railway-provided/configured |

The current staging Railway service has no `SUPABASE_SERVICE_KEY` variable. The service must not use a publishable key for privileged ledger operations. Missing server credentials must continue to produce fail-closed 503 responses.

## 3. Database release

1. Confirm the target project is the approved environment and reports healthy.
2. Apply the ordered Passport migrations recorded in Supabase migration history.
3. Verify every `vgs_agent_identity_*`, `vgs_agent_identities`, `vgs_agent_delegations` and `vgs_agent_authority_commitments` table has RLS enabled.
4. Verify `anon` and `authenticated` have no direct ledger table privileges.
5. Verify only `service_role` can execute the `vgs_*` SECURITY DEFINER functions.
6. Verify each SECURITY DEFINER function has a fixed safe search path.
7. Run Supabase security, health and performance advisors. Resolve all security findings and unindexed foreign keys; unused indexes on an empty staging database are informational and should be reviewed after representative traffic exists.
8. Take a backup and perform a restore rehearsal before production traffic.

Never apply a staging migration to production without checking its SQL, migration order, backup and rollback implications.

## 4. Auth and tenant bootstrap

1. Configure Supabase Auth site URL and exact redirect allowlist for the intended website origins.
2. Create a test account using the Agent Identity Console.
3. Complete email confirmation where required, then sign in.
4. Create the first tenant through the authenticated `POST /v1/agent-identity/tenants` route.
5. Confirm the tenant and owner membership were committed together.
6. Confirm an unauthenticated request, an unrelated user and a suspended tenant cannot access the tenant.
7. Do not insert membership rows using client-supplied user IDs.

## 5. Mandatory staging acceptance tests

Use synthetic data and two independent test tenants/users.

- Supabase token validation, expiry and invalid-token rejection.
- Tenant creation and owner membership atomicity.
- Cross-tenant read/write denial for every route.
- API key scope enforcement, one-time display, expiry and revocation.
- Agent registration with Ed25519 proof-of-possession.
- Challenge expiry, replay rejection and wrong-key rejection.
- Passport signature verification and claim-tamper rejection.
- Key rotation, old-key invalidation and explicit key revocation.
- Agent revocation and downstream delegation/commitment invalidation.
- Delegation scope, grantor capability and expiry checks.
- Exact canonical parameter binding and changed-parameter rejection.
- Commitment expiry and single-consume semantics.
- Two simultaneous consume attempts: exactly one can succeed.
- Process restart and two-instance tests against the same database.
- Receipt signature verification and persistence failure handling.
- CORS preflight from approved website origins; reject unknown origins.
- Rate limiting and abuse controls for authentication, challenges and API-key creation.
- Backup restore and recovery of signing material.

A passing unit test is not a substitute for these live integration tests.

## 6. Customer actuator contract

The API evaluates and consumes an authorization commitment; it does not invoke a customer's payment, deployment or other actuator.

A customer adapter must:
1. Verify the signed decision and action digest.
2. Call consume immediately before the protected action.
3. Execute only if consume returns the expected commitment, tenant, agent, key, action digest and a valid signed receipt.
4. Bind the actuator request to the exact evaluated parameters.
5. Fail closed on timeout, malformed response, missing receipt, replay or signature failure.
6. Record the actuator's own outcome separately. A VeriSigil authority receipt is not proof that the external action succeeded.

Do not describe this integration as universal non-bypass enforcement until each supported actuator adapter has its own adversarial test evidence.

## 7. Production go/no-go

Production release requires all of the following:

- Dedicated production database and Railway service, not the staging project.
- Environment-specific Supabase secret key and issuer-signing material.
- All database migrations reviewed, applied and verified.
- Authenticated tenant onboarding completed in staging.
- Full live acceptance suite passed, including concurrency and restart.
- Independent security review/penetration test findings closed or formally accepted.
- Rate limiting, abuse monitoring, alerting and incident response configured.
- Backups and restore rehearsal verified.
- Key rotation, revocation and incident runbooks rehearsed.
- Production domain, TLS, CORS and security headers checked.
- Customer actuator adapter tested in a controlled pilot.
- Website copy and Swagger environment accurately reflect deployed capabilities.
- Named release owner and rollback approval recorded.

## 8. Deployment and rollback

1. Deploy the approved immutable API commit to the isolated staging service.
2. Run smoke tests, full Passport acceptance tests and security regression.
3. Record commit SHA, migration versions, environment configuration names (never secret values), test results and reviewer.
4. Deploy production only after a separate go/no-go approval.
5. Monitor health, error rates, authentication failures, denied actions, database latency and receipt persistence.
6. If a release fails, roll the API service back to the last known-good immutable deployment and keep the database fail-closed. Prefer forward-only corrective migrations; do not casually drop identity ledger tables or reverse applied production migrations.
7. Reconcile any consumed commitments or incomplete receipts before re-enabling actuator integrations.

## 9. Current staging facts

- Supabase staging project: `lgyxxxvlxlynylhjxbxb` (PostgreSQL 17, healthy).
- Seven migrations are recorded, including tenant foreign-key index coverage.
- Supabase security and health advisors report no findings.
- Performance advisor reports unused indexes while the ledger is empty; no unindexed foreign-key findings remain.
- Railway staging service is deployed and reports a successful deployment and healthy process.
- The `SUPABASE_SERVICE_KEY` is still absent from the Railway variable set. Consequently the live Auth-to-database tenant onboarding and ledger round-trip have not yet been proven.
- Production has not been changed.

**Release state: NOT APPROVED FOR PRODUCTION until every gate above is evidenced.**
