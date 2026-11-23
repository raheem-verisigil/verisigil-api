-- Query-performance hardening for the isolated Passport schema.
-- Remove the redundant single-column agent FK; the composite tenant FK remains.
alter table public.vgs_agent_authority_commitments
  drop constraint if exists vgs_agent_authority_commitments_agent_id_fkey;

create index if not exists vgs_agent_authority_commitments_agent_tenant_idx
  on public.vgs_agent_authority_commitments(org_id, agent_id);

create index if not exists vgs_agent_authority_commitments_key_tenant_idx
  on public.vgs_agent_authority_commitments(org_id, key_id);

create index if not exists vgs_agent_authority_commitments_delegation_idx
  on public.vgs_agent_authority_commitments(delegation_id)
  where delegation_id is not null;

create index if not exists vgs_agent_delegations_grantor_idx
  on public.vgs_agent_delegations(org_id, grantor_agent_id);

create index if not exists vgs_agent_identity_memberships_user_status_idx
  on public.vgs_agent_identity_memberships(user_id, status, org_id);
