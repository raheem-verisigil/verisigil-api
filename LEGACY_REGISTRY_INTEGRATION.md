# VeriSigil legacy registry integration

## Restored database

The restored project `VeriSigilAI Project` is retained as the legacy registry and integration target. It contains existing principal, authority, release, verifier, governance, audit, and proof records. These records are not automatically copied, renamed, or discarded.

## Registry responsibilities

- `organisations`: canonical organisation identifier and legacy plan metadata.
- `vgs_agent_identity_tenants`: authenticated tenant status and verified owner membership boundary.
- `agents`: existing canonical agent directory; each new Cryptographic Passport agent is mirrored here using the same tenant and agent UUID.
- `passports`: existing Passport history; registration and key rotation append a Passport version, and revocation marks the affected versions revoked.
- `vgs_agent_identities` and `vgs_agent_identity_keys`: authoritative signed Passport claims, Ed25519 key fingerprints, key state and tenant-scoped identity records.
- `vgs_agent_delegations` and `vgs_agent_authority_commitments`: bounded delegation and exact-action authorization ledger.
- `vgs_proof_events`: receives privacy-minimised identity, key, and authority lifecycle events from database triggers.
- `vgs_principals` and `vgs_authority_records`: retained as the legacy principal/authority registry. Existing self-declared/test records are not silently promoted into cryptographic agent identities or runtime delegations. Any future mapping must be explicit and reviewed.

## Safety and migration order

1. Keep the original production API and its database connection unchanged during integration.
2. Apply the seven reviewed Passport migrations in timestamp order to the restored project.
3. Apply `20261123190000_legacy_registry_bridge.sql` only after the seven Passport migrations are present.
4. Verify the organisation/tenant and agent/passport foreign keys, lifecycle mirroring, and proof-event triggers.
5. Run tenant onboarding and agent registration/rotation/revocation tests with synthetic Auth users and agents.
6. Verify legacy records remain unchanged and count-stable.
7. Complete cross-tenant denial, concurrent consume, restart/two-instance, backup restore, and actuator adapter acceptance tests before production cutover.

## Current release limits

The staging implementation currently uses Ed25519. Do not claim Dilithium/post-quantum support or active Z3 verification unless separately implemented and verified. VeriSigil evaluates and consumes authorization; a customer adapter must enforce the consume result at the protected actuator.
