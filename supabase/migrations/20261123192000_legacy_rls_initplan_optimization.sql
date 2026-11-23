-- Avoid per-row evaluation of auth.role() in legacy server-only policies.
-- The scalar subquery preserves semantics while allowing init-plan evaluation.
alter policy service_role_only on public.approval_requests using ((select auth.role()) = 'service_role'::text);
alter policy service_role_only on public.customers using ((select auth.role()) = 'service_role'::text);
alter policy service_role_only on public.evidence_bundles using ((select auth.role()) = 'service_role'::text);
alter policy service_role_only on public.passports using ((select auth.role()) = 'service_role'::text);
alter policy service_role_only on public.scan_reports using ((select auth.role()) = 'service_role'::text);
alter policy service_role_only on public.sigilguard_events using ((select auth.role()) = 'service_role'::text);
alter policy "Service role full access" on public.terrex_compliance_reports using ((select auth.role()) = 'service_role'::text);
alter policy "Service role full access" on public.terrex_intercepts using ((select auth.role()) = 'service_role'::text);
alter policy "Service role full access" on public.terrex_ledger using ((select auth.role()) = 'service_role'::text);
alter policy service_role_only on public.treasury_mandates using ((select auth.role()) = 'service_role'::text);
alter policy service_role_only on public.trust_score_history using ((select auth.role()) = 'service_role'::text);
alter policy service_role_only on public.verifiers using ((select auth.role()) = 'service_role'::text);
alter policy service_role_only on public.waitlist using ((select auth.role()) = 'service_role'::text);
