# VeriSigil production acceptance

Configure these repository Actions secrets before running **VeriSigil authenticated staging acceptance**:

- `VERISIGIL_STAGING_SUPABASE_URL`: URL of the isolated VeriSigil staging project.
- `VERISIGIL_STAGING_SUPABASE_ANON_KEY`: enabled publishable/anon key for that same project.
- `VERISIGIL_STAGING_SUPABASE_SERVICE_KEY`: server-only service credential for that same staging project. Never use the production credential.

The API URL is pinned to the isolated Passport staging Railway service. The script refuses to run unless both URLs identify staging.

The workflow creates synthetic Supabase Auth users and tests tenant-owner onboarding, tenant API-key issuance/revocation, Ed25519 proof-of-possession, Passport issuance, challenge replay denial, bounded delegation, exact-parameter authority evaluation, receipt retrieval, concurrent one-time consume (exactly one success), and cross-tenant denial.

Generated synthetic rows and Auth users are removed in a finally cleanup path. Cleanup warnings fail the run. Use this only against the isolated staging database.

A green lifecycle workflow does not itself prove backup restoration, load behaviour, external customer actuator enforcement, independent penetration testing, or production cutover. Those require separate evidence.
