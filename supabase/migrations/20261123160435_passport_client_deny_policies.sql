-- Explicitly deny direct client-role access to the identity ledger.
-- The FastAPI service accesses these tables with its server-side service role;
-- no anon/authenticated table grants are issued by the base migration.
do $$
declare t text;
begin
  foreach t in array array[
    'vgs_agent_identity_memberships',
    'vgs_agent_identity_api_keys',
    'vgs_agent_identities',
    'vgs_agent_identity_keys',
    'vgs_agent_identity_challenges',
    'vgs_agent_delegations',
    'vgs_agent_authority_commitments'
  ] loop
    execute format(
      'drop policy if exists %I on public.%I',
      t || '_deny_client_roles', t
    );
    execute format(
      'create policy %I on public.%I for all to anon, authenticated using (false) with check (false)',
      t || '_deny_client_roles', t
    );
  end loop;
end $$;

alter table public.vgs_agent_identity_api_keys
  add constraint vgs_agent_identity_api_keys_scopes_array
  check (jsonb_typeof(scopes) = 'array');

alter table public.vgs_agent_identities
  add constraint vgs_agent_identities_capabilities_array
  check (jsonb_typeof(capabilities) = 'array');

alter table public.vgs_agent_identity_challenges
  add constraint vgs_agent_identity_challenges_expiry_after_creation
  check (expires_at > created_at);

alter table public.vgs_agent_delegations
  add constraint vgs_agent_delegations_scopes_array
  check (jsonb_typeof(scopes) = 'array'),
  add constraint vgs_agent_delegations_expiry_after_issue
  check (expires_at > issued_at);

alter table public.vgs_agent_authority_commitments
  add constraint vgs_agent_authority_commitments_parameters_object
  check (jsonb_typeof(parameters) = 'object'),
  add constraint vgs_agent_authority_commitments_reasons_array
  check (jsonb_typeof(reasons) = 'array'),
  add constraint vgs_agent_authority_commitments_receipt_objects
  check (
    jsonb_typeof(decision_receipt) = 'object'
    and (consumption_receipt is null or jsonb_typeof(consumption_receipt) = 'object')
  ),
  add constraint vgs_agent_authority_commitments_expiry_after_evaluation
  check (expires_at > evaluated_at);
