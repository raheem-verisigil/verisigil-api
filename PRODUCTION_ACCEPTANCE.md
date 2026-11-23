# VeriSigil production acceptance

Configure these repository Actions secrets before running **VeriSigil authenticated staging acceptance**:

- `VERISIGIL_STAGING_SUPABASE_SERVICE_KEY`: server-only service credential for the isolated `VeriSigil-Isolated-Staging` project. Never use the production credential. The standard `SUPABASE_SERVICE_KEY` alias is also accepted.

The API URL, Supabase URL, and public publishable key are pinned to the isolated staging services in the workflow. The script checks the exact staging Supabase project reference and refuses any other database.

The workflow creates synthetic Supabase Auth users and tests tenant-owner onboarding, tenant API-key issuance/revocation, Ed25519 proof-of-possession, Passport issuance, challenge replay denial, bounded delegation, exact-parameter authority evaluation, receipt retrieval, concurrent one-time consume (exactly one success), and cross-tenant denial.

Generated synthetic rows and Auth users are removed in a finally cleanup path. Cleanup warnings fail the run. Use this only against the isolated staging database.

A green lifecycle workflow does not itself prove backup restoration, load behaviour, external customer actuator enforcement, independent penetration testing, or production cutover. Those require separate evidence.


## Legacy database hardening already applied
The restored legacy project now has explicit `USING (false) WITH CHECK (false)` policies on every public RLS-enabled table that previously had no policy. The migration also revokes all table privileges from `anon` and `authenticated` on those tables, including `TRUNCATE`, `MAINTAIN`, `TRIGGER`, and `REFERENCES`, while leaving `service_role` and database owners untouched. Post-migration checks returned zero RLS-enabled tables without policies, zero remaining client table grants across the affected legacy tables, and no Supabase security or health advisor lints.

## Final production release blockers

1. Configure the one isolated-staging service credential secret above and obtain a green authenticated lifecycle workflow. The workflow currently fails closed because that service credential is absent.
2. Run a Supabase backup restoration rehearsal to a separate recovery target (never overwrite the source project). Record backup timestamp, restored project reference, schema/migration checks, row-count/integrity checks, and successful application smoke tests. The connected Supabase database tools do not expose backup restore controls, so this must be completed in the Supabase dashboard.
3. Exercise the concurrency/replay suite with at least two staging API replicas and verify restart/recovery against the same persistent database.
4. Integrate a real customer-side actuator adapter. It must independently enforce the consume response and reject execution on denial, timeout, signature failure, stale commitment, or replay. VeriSigil's API returns evidence/authority; it does not invoke or control a customer's actuator.
5. Complete independent security review, alerting/incident response rehearsal, and a controlled production rollback rehearsal before promoting any candidate.

Do not mark production ready until these are evidenced. Current staging crypto support is Ed25519; do not advertise post-quantum signatures or active Z3 formal proof verification.
