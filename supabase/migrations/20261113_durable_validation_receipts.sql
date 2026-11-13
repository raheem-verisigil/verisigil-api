-- VeriSigil staging-only migration: durable, one-time execution receipts.
-- Apply to the dedicated staging Supabase project before deploying the runtime
-- that imports durable_validation_receipts.py. Do not run against production.

create table if not exists public.vgs_validation_receipts (
    revalidation_id text primary key,
    proposal_id text not null,
    receipt jsonb not null,
    record jsonb not null,
    created_at timestamptz not null default now(),
    consumed_at timestamptz,
    consumed_proposal_id text,
    constraint vgs_validation_receipts_consumption_pair
      check ((consumed_at is null and consumed_proposal_id is null)
          or (consumed_at is not null and consumed_proposal_id is not null))
);

create index if not exists vgs_validation_receipts_proposal_created_idx
    on public.vgs_validation_receipts (proposal_id, created_at desc);

alter table public.vgs_validation_receipts enable row level security;
revoke all on public.vgs_validation_receipts from anon, authenticated;
grant select, insert, update on public.vgs_validation_receipts to service_role;

create or replace function public.vgs_consume_validation_receipt(
    p_revalidation_id text,
    p_proposal_id text
) returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
    consumed_record jsonb;
begin
    update public.vgs_validation_receipts
       set consumed_at = now(),
           consumed_proposal_id = p_proposal_id
     where revalidation_id = p_revalidation_id
       and proposal_id = p_proposal_id
       and consumed_at is null
    returning record into consumed_record;

    return consumed_record;
end;
$$;

revoke all on function public.vgs_consume_validation_receipt(text, text) from public, anon, authenticated;
grant execute on function public.vgs_consume_validation_receipt(text, text) to service_role;
