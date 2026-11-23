-- Complete tenant-consistent foreign keys for the Passport ledger.
-- All target tables are empty in this isolated staging database.
alter table public.vgs_agent_identity_memberships
  add constraint vgs_agent_identity_memberships_auth_user_fk
  foreign key (user_id) references auth.users(id);

alter table public.vgs_agent_identity_api_keys
  add constraint vgs_agent_identity_api_keys_creator_membership_fk
  foreign key (created_by, org_id)
  references public.vgs_agent_identity_memberships(user_id, org_id);

alter table public.vgs_agent_identity_challenges
  add constraint vgs_agent_identity_challenges_agent_tenant_fk
  foreign key (org_id, agent_id)
  references public.vgs_agent_identities(org_id, agent_id);

alter table public.vgs_agent_delegations
  add constraint vgs_agent_delegations_org_id_delegation_id_key
  unique (org_id, delegation_id);

alter table public.vgs_agent_authority_commitments
  drop constraint if exists vgs_agent_authority_commitments_delegation_id_fkey;

alter table public.vgs_agent_authority_commitments
  add constraint vgs_agent_authority_commitments_delegation_tenant_fk
  foreign key (org_id, delegation_id)
  references public.vgs_agent_delegations(org_id, delegation_id);

create index if not exists vgs_agent_identity_challenges_agent_tenant_idx
  on public.vgs_agent_identity_challenges(org_id, agent_id)
  where agent_id is not null;

create index if not exists vgs_agent_authority_commitments_delegation_tenant_idx
  on public.vgs_agent_authority_commitments(org_id, delegation_id)
  where delegation_id is not null;
