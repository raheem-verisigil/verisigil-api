-- Cover tenant foreign keys used during tenant deletion/update checks and scoped lookups.
create index if not exists vgs_agent_identity_api_keys_tenant_idx
  on public.vgs_agent_identity_api_keys(org_id);
create index if not exists vgs_agent_identity_memberships_tenant_idx
  on public.vgs_agent_identity_memberships(org_id);
