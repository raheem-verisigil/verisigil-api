# Cryptographic Passport identity layer — staging integration

## Purpose and boundary

This integration extends the existing VeriSigil FastAPI application. It does not replace the legacy passport routes or create a second FastAPI app.

The new layer adds a tenant-scoped agent identity record, Ed25519 proof-of-possession, signed passport claims, key rotation/revocation, bounded direct delegation, and a two-step runtime-authority decision/consume flow.

A Cryptographic Passport identifies an agent and its issuer-signed claims. It is not blanket permission. Runtime authority is re-evaluated against the exact action and parameters, and an authorization commitment must be consumed once at the protected boundary.

**No agent private key is submitted to or stored by VeriSigil.** The agent signs challenges and runtime requests locally. VeriSigil stores public keys only.

## Source integration

- Core application: `main.py` (the existing 5.86 MB monolithic FastAPI application).
- Runtime entrypoint: `verisigil_entrypoint.py` imports the existing core app and registers the new router.
- New API module: `agent_identity_layer.py`.
- Database migration: `supabase/migrations/20261123_cryptographic_passport_identity.sql`.
- Regression tests: `tests/test_agent_identity_layer.py`.

The new endpoints are attached to `core.app`; existing route handlers are not replaced.

## Authentication and tenant isolation

Two authentication modes are supported:

1. **Supabase access token** — the API asks Supabase Auth `/auth/v1/user` to validate the bearer token, then resolves an ACTIVE membership from `vgs_agent_identity_memberships`.
2. **Tenant API key** — the API hashes the supplied key with SHA-256 and looks up the active key record. The raw key is shown only once at creation.

The caller cannot set a tenant by submitting an `org_id` in a request body. A user with one active membership uses it automatically. A user with multiple memberships must select one using `x-org-id`, and it must match an active membership.

The new routes do not accept the legacy global production API key as a tenant credential. This avoids silently assigning a global credential to an arbitrary tenant. The staging entrypoint also replaces the legacy core API-key validator with an environment-only validator, so source-embedded demo/sandbox strings are no longer accepted by the active staging entrypoint. The legacy literals remain in the large historical core source file pending a separate source-file cleanup; they are not valid credentials through the active staging entrypoint.

### Bootstrap

After applying the migration to the isolated staging Supabase project, a database administrator must create the tenant membership using the verified Supabase Auth user UUID and the intended tenant UUID:

```sql
insert into public.vgs_agent_identity_memberships(user_id, org_id, role)
values ('<verified-auth-user-uuid>', '<tenant-uuid>', 'owner');
```

Do not accept either UUID from an untrusted client as proof of membership. Tenant owners can then create scoped API keys through `POST /v1/agent-identity/api-keys`.

## API surface

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/agent-identity/api-keys` | Create a tenant-scoped, hashed API key (verified tenant owner only) |
| POST | `/v1/agent-identity/api-keys/{key_id}/revoke` | Revoke a tenant API key (verified tenant owner only) |
| POST | `/v1/agent-identity/challenges` | Issue a short-lived Ed25519 proof-of-possession challenge |
| POST | `/v1/agent-identity/agents` | Register an agent and issue a signed Cryptographic Passport |
| GET | `/v1/agent-identity/agents` | List agents within the authenticated tenant |
| GET | `/v1/agent-identity/agents/{agent_id}` | Inspect passport and public-key status |
| POST | `/v1/agent-identity/agents/{agent_id}/keys` | Rotate an agent key with proof-of-possession |
| POST | `/v1/agent-identity/keys/{key_id}/revoke` | Revoke an Ed25519 public key |
| POST | `/v1/agent-identity/agents/{agent_id}/revoke` | Revoke agent, keys, delegations and pending commitments |
| POST | `/v1/agent-identity/delegations` | Create direct, bounded agent-to-agent delegation |
| POST | `/v1/agent-identity/delegations/{delegation_id}/revoke` | Revoke a delegation |
| POST | `/v1/runtime/authority/evaluate` | Evaluate authority for exact action parameters |
| POST | `/v1/runtime/authority/consume` | Atomically consume one authorization commitment |
| GET | `/v1/runtime/authority/receipts/{commitment_id}` | Retrieve and verify the signed decision/consumption receipt |

Swagger exposes these operations at `/docs` after the module is registered.

## Registration sequence

1. A tenant operator requests a `REGISTER_AGENT` challenge, providing the agent's Ed25519 public key.
2. The agent signs the exact `sign_this_exact_object` using RFC 8785 JSON Canonicalization Scheme (JCS).
3. The operator submits the challenge ID, public key, signature, agent name and declared capabilities.
4. The server verifies proof-of-possession and atomically consumes the challenge.
5. A database function creates the tenant-bound agent and public-key records in one transaction.
6. VeriSigil signs the passport claims with its existing Ed25519 issuer key.

The passport records issuer, tenant, DID, agent ID, public-key fingerprints, declared capabilities, issue/expiry timestamps and version. A passport signature is verified independently from the agent's proof-of-possession.

## Runtime authority sequence

1. The agent signs the exact tuple `agent_id + key_id + action + parameters + delegation_id`.
2. `POST /v1/runtime/authority/evaluate` checks the issuer-signed passport, agent status, expiry, public-key status/fingerprint, proof-of-possession and action/delegation scope.
3. The API stores a short-lived commitment bound to a SHA-256 digest of the exact canonical action tuple. The evaluation response always has `execution_authorized: false`.
4. At the protected boundary, the agent signs the consume proof for the commitment ID and action digest.
5. `POST /v1/runtime/authority/consume` rechecks current identity and authority, then calls a Postgres function that atomically consumes the commitment only once and rechecks live agent, key, capability and delegation status.
6. A signed consumption receipt is persisted. If receipt persistence is not confirmed, the API does not return execution authorization.

The API does not itself invoke an external actuator. The customer integration must enforce the consume result at the actual action boundary. This implementation does not prove universal non-bypass protection for downstream systems.

## Delegation model

Delegations are direct and tenant-local. A grantor may delegate only capabilities already present in its issuer-signed passport, and expiry cannot exceed either agent passport. Runtime evaluation checks both agents, the delegation status, scope and expiry. Transitive delegation is not enabled by this integration.

## Fail-closed behavior

- Missing or invalid tenant membership: reject.
- Missing database configuration or persistence error: reject.
- Invalid, expired or replayed challenge: reject.
- Invalid passport signature or mismatched public-key fingerprint: reject.
- Revoked/expired agent, key or delegation: reject.
- Action outside declared capability/delegation scope: reject.
- Parameter digest mismatch: reject.
- Expired, revoked or already-consumed commitment: reject.
- No database-confirmed consumption receipt: do not return execution authorization.

## Staging-only activation checklist

1. Review the migration and tests.
2. Apply `20261123_cryptographic_passport_identity.sql` only to the dedicated isolated staging Supabase project.
3. Insert the first tenant membership using a verified Auth user UUID.
4. Set `SUPABASE_URL`, `SUPABASE_ANON_KEY` (or the existing `SUPABASE_KEY` used for Auth), `SUPABASE_SERVICE_KEY` (or `SUPABASE_SERVICE_ROLE_KEY` for PostgREST writes), and the existing `SIGN_SECRET` in the isolated staging service only. Never copy production values into staging.
5. Deploy the staging branch and run the identity regression suite plus API round-trip tests.
6. Test challenge replay, key rotation/revocation, tenant cross-read denial, delegation revocation, exact-parameter mismatch, commitment expiry, two concurrent consume requests and process restart.
7. Only after evidence review should the website describe the endpoints as live.

**This branch does not apply the migration, change Railway variables, restart a service or deploy.** The migration is a reviewed artifact until separately applied. Production is out of scope.
