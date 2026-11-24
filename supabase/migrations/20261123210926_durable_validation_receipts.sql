-- Durable, one-time storage for legacy VGS revalidation receipts.
-- The API uses the service_role key for this table; browser roles receive no access.
create table if not exists public.vgs_validation_receipts (
    revalidation_id text primary key,
    proposal_id text not null,
    receipt jsonb not null,
    record jsonb not null,
    created_at timestamptz not null default now(),
    consumed_at timestamptz,
    constraint vgs_validation_receipts_revalidation_id_nonempty
        check (length(btrim(revalidation_id)) between 1 and 160),
    constraint vgs_validation_receipts_proposal_id_nonempty
        check (length(btrim(proposal_id)) between 1 and 160),
    constraint vgs_validation_receipts_receipt_object
        check (jsonb_typeof(receipt) = 'object'),
    constraint vgs_validation_receipts_record_object
        check (jsonb_typeof(record) = 'object')
);

alter table public.vgs_validation_receipts enable row level security;

revoke all on table public.vgs_validation_receipts from public, anon, authenticated;
grant select, insert, update, delete on table public.vgs_validation_receipts to service_role;

drop policy if exists vgs_validation_receipts_client_deny on public.vgs_validation_receipts;
create policy vgs_validation_receipts_client_deny
    on public.vgs_validation_receipts
    for all
    to anon, authenticated
    using (false)
    with check (false);

create or replace function public.vgs_consume_validation_receipt(
    p_revalidation_id text,
    p_proposal_id text
)
returns jsonb
language sql
security invoker
set search_path = pg_catalog, public
as $function$
    update public.vgs_validation_receipts
       set consumed_at = clock_timestamp()
     where revalidation_id = p_revalidation_id
       and proposal_id = p_proposal_id
       and consumed_at is null
    returning record;
$function$;

revoke all on function public.vgs_consume_validation_receipt(text, text) from public;
revoke all on function public.vgs_consume_validation_receipt(text, text) from anon, authenticated;
grant execute on function public.vgs_consume_validation_receipt(text, text) to service_role;

comment on table public.vgs_validation_receipts is
    'Durable, tenant-independent VGS revalidation receipts consumed exactly once before execution authorization.';
comment on function public.vgs_consume_validation_receipt(text, text) is
    'Atomically consumes one matching revalidation receipt; returns its record once and NULL for replay or proposal mismatch.';
