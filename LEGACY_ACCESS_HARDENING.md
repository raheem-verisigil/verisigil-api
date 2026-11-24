# Legacy database access hardening

The restored legacy project had several permissive policies that allowed anonymous/authenticated clients to read operational records or write without server authority. The additive hardening migration removes raw-client access from approval requests, scan reports, audit logs, verifier credentials, release records, and Sigilmark issuance. The public Sigilmark read path is retained for proof inspection; all issuance and mutation are server-side.

The existing API's service-role access remains intact. Browser integrations must call the API and must not query these raw tables with a publishable key.

The migration also pins three legacy function search paths and adds indexes for foreign keys flagged by Supabase's performance advisor. It removes one redundant duplicate index. RLS-enabled tables with no policies remain deny-by-default; they are intentionally server-only until explicit tenant-scoped client policies are designed.
