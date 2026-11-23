-- Self-service tenant provisioning for authenticated VeriSigil customers.
create table if not exists public.vgs_agent_identity_tenants (
  org_id uuid primary key,
  tenant_name text not null
    check (char_length(btrim(tenant_name)) between 2 and 120),
  status text not null default 'ACTIVE'
    check (status in ('ACTIVE','SUSPENDED','CLOSED')),
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now()
);

alter table public.vgs_agent_identity_memberships
  add constraint vgs_agent_identity_memberships_tenant_fk
  foreign key (org_id) references public.vgs_agent_identity_tenants(org_id);

alter table public.vgs_agent_identity_api_keys
  add constraint vgs_agent_identity_api_keys_tenant_fk
  foreign key (org_id) references public.vgs_agent_identity_tenants(org_id);

alter table public.vgs_agent_identities
  add constraint vgs_agent_identities_tenant_fk
  foreign key (org_id) references public.vgs_agent_identity_tenants(org_id);

alter table public.vgs_agent_identity_keys
  add constraint vgs_agent_identity_keys_tenant_fk
  foreign key (org_id) references public.vgs_agent_identity_tenants(org_id);

alter table public.vgs_agent_identity_challenges
  add constraint vgs_agent_identity_challenges_tenant_fk
  foreign key (org_id) references public.vgs_agent_identity_tenants(org_id);

alter table public.vgs_agent_delegations
  add constraint vgs_agent_delegations_tenant_fk
  foreign key (org_id) references public.vgs_agent_identity_tenants(org_id);

alter table public.vgs_agent_authority_commitments
  add constraint vgs_agent_authority_commitments_tenant_fk
  foreign key (org_id) references public.vgs_agent_identity_tenants(org_id);

alter table public.vgs_agent_identity_tenants enable row level security;
revoke all on public.vgs_agent_identity_tenants from anon, authenticated;
grant select, insert, update, delete on public.vgs_agent_identity_tenants to service_role;
create policy vgs_agent_identity_tenants_deny_client_roles
  on public.vgs_agent_identity_tenants
  for all to anon, authenticated
  using (false) with check (false);

create index if not exists vgs_agent_identity_tenants_creator_idx
  on public.vgs_agent_identity_tenants(created_by, created_at desc);

create or replace function public.vgs_create_agent_identity_tenant(
  p_org_id uuid, p_user_id uuid, p_tenant_name text
) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public
as $$
declare
  tenant_row public.vgs_agent_identity_tenants%rowtype;
  membership_row public.vgs_agent_identity_memberships%rowtype;
  clean_name text := btrim(coalesce(p_tenant_name, ''));
begin
  if p_org_id is null or p_user_id is null
     or char_length(clean_name) < 2 or char_length(clean_name) > 120 then
    raise exception 'Invalid tenant onboarding request';
  end if;

  insert into public.vgs_agent_identity_tenants
    (org_id, tenant_name, status, created_by)
  values (p_org_id, clean_name, 'ACTIVE', p_user_id)
  returning * into tenant_row;

  insert into public.vgs_agent_identity_memberships
    (user_id, org_id, role, status)
  values (p_user_id, p_org_id, 'owner', 'ACTIVE')
  returning * into membership_row;

  return jsonb_build_object(
    'tenant', to_jsonb(tenant_row),
    'membership', to_jsonb(membership_row)
  );
end;
$$;

revoke all on function public.vgs_create_agent_identity_tenant(uuid,uuid,text)
  from public, anon, authenticated;
grant execute on function public.vgs_create_agent_identity_tenant(uuid,uuid,text)
  to service_role;
