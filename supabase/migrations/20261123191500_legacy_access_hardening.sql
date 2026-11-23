-- Harden restored legacy tables that were exposed by permissive RLS policies.
-- Service-role backend access remains available (service_role bypasses RLS).
-- Browser/anon roles must use authenticated API routes, not read/write raw ledgers.

drop policy if exists "Public can read approvals" on public.approval_requests;
drop policy if exists "Public can read scan reports" on public.scan_reports;
drop policy if exists audit_log_public_read on public.audit_log;
drop policy if exists audit_log_service_insert on public.audit_log;

-- The old verifier policies were TO PUBLIC with unconditional INSERT/UPDATE
-- checks. This exposed verifier API-key material and allowed client writes.
drop policy if exists verifiers_public_read on public.verifiers;
drop policy if exists verifiers_service_insert on public.verifiers;
drop policy if exists verifiers_service_update on public.verifiers;

-- The old release-record policies were TO PUBLIC and effectively unrestricted.
drop policy if exists allow_insert_service_role on public.release_records;
drop policy if exists service_role_all on public.release_records;

-- Sigilmarks remain publicly readable for proof inspection, but creation and
-- mutation must be performed only by the server-side API.
drop policy if exists allow_all_insert on public.sigilmarks;

-- Pin search_path for the three legacy functions flagged by the database advisor.
alter function public.vcb_prevent_mandate_reinstate()
  set search_path = pg_catalog, public;
alter function public.consume_sigilmark(text, text)
  set search_path = pg_catalog, public;
alter function public.vcb_prevent_unconsume()
  set search_path = pg_catalog, public;

-- Cover legacy foreign keys flagged by the performance advisor.
create index if not exists evidence_bundles_agent_id_idx
  on public.evidence_bundles(agent_id);
create index if not exists evidence_bundles_org_id_idx
  on public.evidence_bundles(org_id);
create index if not exists governance_events_org_id_idx
  on public.governance_events(org_id);
create index if not exists passports_agent_id_idx
  on public.passports(agent_id);
create index if not exists vcb_ledger_sigilmark_id_idx
  on public.vcb_ledger(sigilmark_id);
create index if not exists vgs_authority_records_principal_id_idx
  on public.vgs_authority_records(principal_id);

-- Remove the duplicate non-primary-key index identified by the advisor.
drop index if exists public.idx_sigilmarks_id;
