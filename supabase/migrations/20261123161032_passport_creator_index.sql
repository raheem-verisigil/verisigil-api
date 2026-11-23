create index if not exists vgs_agent_identity_api_keys_creator_membership_idx
  on public.vgs_agent_identity_api_keys(created_by, org_id);
