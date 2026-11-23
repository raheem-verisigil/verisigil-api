-- Additive bridge between the restored VeriSigil registry and the Cryptographic Passport layer.
-- Preserves all existing principals, authority records, release records and verifier rows.
-- New tenant/agent registrations are mirrored into the established organisations/agents/passports
-- registry, while the new ledger remains the source of cryptographic proof and runtime authority.

create unique index if not exists agents_org_id_id_uidx
  on public.agents(org_id, id);

create index if not exists passports_org_agent_issued_idx
  on public.passports(org_id, agent_id, issued_at desc);

alter table public.vgs_agent_identity_tenants
  add constraint vgs_agent_identity_tenants_legacy_org_fk
  foreign key (org_id) references public.organisations(id) on delete restrict;

alter table public.vgs_agent_identities
  add constraint vgs_agent_identities_legacy_agent_fk
  foreign key (org_id, agent_id) references public.agents(org_id, id) on delete restrict;

alter table public.passports
  add constraint passports_org_agent_integrity_fk
  foreign key (org_id, agent_id) references public.agents(org_id, id) on delete restrict;

-- Tenant creation now creates the canonical organisation and the Passport tenant
-- under the same UUID, then creates the first verified owner membership atomically.
create or replace function public.vgs_create_agent_identity_tenant(
  p_org_id uuid, p_user_id uuid, p_tenant_name text
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public
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

  insert into public.organisations (id, name)
  values (p_org_id, clean_name);

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

-- Agent registration writes one logical identity into the canonical legacy registry
-- and the new tenant-scoped cryptographic ledger in the same database transaction.
create or replace function public.vgs_create_agent_identity(
  p_agent jsonb, p_key jsonb
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  a jsonb;
  k jsonb;
begin
  if (p_agent->>'org_id')::uuid <> (p_key->>'org_id')::uuid
     or (p_agent->>'agent_id')::uuid <> (p_key->>'agent_id')::uuid then
    raise exception 'Agent and key tenant/identity binding mismatch';
  end if;

  insert into public.agents (id, org_id, name, did, trust_score, status)
  values (
    (p_agent->>'agent_id')::uuid,
    (p_agent->>'org_id')::uuid,
    p_agent->>'agent_name',
    p_agent->>'did',
    1.0,
    'ACTIVE'
  );

  insert into public.vgs_agent_identities as inserted
    (agent_id, org_id, agent_name, did, passport, capabilities, status, issued_at, expires_at)
  values (
    (p_agent->>'agent_id')::uuid,
    (p_agent->>'org_id')::uuid,
    p_agent->>'agent_name',
    p_agent->>'did',
    p_agent->'passport',
    p_agent->'capabilities',
    p_agent->>'status',
    (p_agent->>'issued_at')::timestamptz,
    (p_agent->>'expires_at')::timestamptz
  )
  returning to_jsonb(inserted) into a;

  insert into public.passports
    (agent_id, org_id, trust_score, status, metadata, issued_at)
  values (
    (p_agent->>'agent_id')::uuid,
    (p_agent->>'org_id')::uuid,
    1.0,
    'ACTIVE',
    jsonb_build_object(
      'identity_schema', 'VERISIGIL-CRYPTOGRAPHIC-PASSPORT-1.0',
      'cryptographic_passport', p_agent->'passport',
      'capabilities', p_agent->'capabilities'
    ),
    (p_agent->>'issued_at')::timestamptz
  );

  insert into public.vgs_agent_identity_keys as inserted
    (key_id, org_id, agent_id, public_key_b64, fingerprint, algorithm, status)
  values (
    p_key->>'key_id',
    (p_key->>'org_id')::uuid,
    (p_key->>'agent_id')::uuid,
    p_key->>'public_key_b64',
    p_key->>'fingerprint',
    p_key->>'algorithm',
    p_key->>'status'
  )
  returning to_jsonb(inserted) into k;

  return jsonb_build_object('agent', a, 'key', k);
end;
$$;

-- A rotation produces a new legacy Passport version without erasing the old one.
-- The new tenant-scoped identity record remains the authoritative current state.
create or replace function public.vgs_rotate_agent_identity_key(
  p_org_id uuid, p_agent_id uuid, p_key jsonb, p_passport jsonb,
  p_replace_existing boolean default true
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  a jsonb;
  k jsonb;
  issued_at timestamptz;
begin
  update public.vgs_agent_identities as target
     set passport = p_passport, updated_at = clock_timestamp()
   where org_id = p_org_id
     and agent_id = p_agent_id
     and status = 'ACTIVE'
     and expires_at > clock_timestamp()
  returning to_jsonb(target) into a;

  if a is null then
    return null;
  end if;

  if p_replace_existing then
    update public.vgs_agent_identity_keys as target
       set status = 'ROTATED', revoked_at = clock_timestamp()
     where org_id = p_org_id
       and agent_id = p_agent_id
       and status = 'ACTIVE';
  end if;

  update public.passports
     set status = 'REVOKED'
   where org_id = p_org_id
     and agent_id = p_agent_id
     and status = 'ACTIVE';

  issued_at := coalesce((p_passport->'claims'->>'issued_at')::timestamptz, clock_timestamp());

  insert into public.passports
    (agent_id, org_id, trust_score, status, metadata, issued_at)
  values (
    p_agent_id,
    p_org_id,
    1.0,
    'ACTIVE',
    jsonb_build_object(
      'identity_schema', 'VERISIGIL-CRYPTOGRAPHIC-PASSPORT-1.0',
      'cryptographic_passport', p_passport
    ),
    issued_at
  );

  insert into public.vgs_agent_identity_keys as inserted
    (key_id, org_id, agent_id, public_key_b64, fingerprint, algorithm, status)
  values (
    p_key->>'key_id',
    p_org_id,
    p_agent_id,
    p_key->>'public_key_b64',
    p_key->>'fingerprint',
    'Ed25519',
    'ACTIVE'
  )
  returning to_jsonb(inserted) into k;

  return jsonb_build_object('agent', a, 'key', k);
end;
$$;

-- Revocation is reflected in both registries so legacy consumers cannot continue
-- to treat an agent or its Passport as active.
create or replace function public.vgs_revoke_agent_identity(
  p_org_id uuid, p_agent_id uuid
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  key_count integer;
  delegation_count integer;
begin
  update public.vgs_agent_identities
     set status = 'REVOKED', updated_at = clock_timestamp()
   where org_id = p_org_id
     and agent_id = p_agent_id
     and status <> 'REVOKED';

  update public.agents
     set status = 'REVOKED'
   where org_id = p_org_id
     and id = p_agent_id;

  update public.passports
     set status = 'REVOKED'
   where org_id = p_org_id
     and agent_id = p_agent_id
     and status <> 'REVOKED';

  update public.vgs_agent_identity_keys
     set status = 'REVOKED', revoked_at = clock_timestamp()
   where org_id = p_org_id
     and agent_id = p_agent_id
     and status = 'ACTIVE';
  get diagnostics key_count = row_count;

  update public.vgs_agent_delegations
     set status = 'REVOKED', revoked_at = clock_timestamp()
   where org_id = p_org_id
     and status = 'ACTIVE'
     and (grantor_agent_id = p_agent_id or grantee_agent_id = p_agent_id);
  get diagnostics delegation_count = row_count;

  update public.vgs_agent_authority_commitments
     set decision = 'REFUSED', reasons = jsonb_build_array('AGENT_REVOKED')
   where org_id = p_org_id
     and agent_id = p_agent_id
     and consumed_at is null
     and decision = 'AUTHORIZED';

  return jsonb_build_object(
    'agent_id', p_agent_id,
    'revoked_keys', key_count,
    'revoked_delegations', delegation_count
  );
end;
$$;

-- Mirror identity lifecycle and authority outcomes into the existing proof-event
-- stream. Only identifiers, digests and state transitions are emitted; raw
-- parameters, public-key material and API-key material are never copied.
create or replace function public.vgs_write_agent_identity_proof_event()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  new_row jsonb := to_jsonb(NEW);
  old_row jsonb := case when TG_OP = 'UPDATE' then to_jsonb(OLD) else '{}'::jsonb end;
  event_name text;
  subject text;
  event_data jsonb;
begin
  if TG_TABLE_NAME = 'vgs_agent_identities' then
    if TG_OP = 'INSERT' then
      event_name := 'AGENT_IDENTITY_REGISTERED';
    elsif old_row->>'status' is distinct from new_row->>'status' then
      event_name := 'AGENT_IDENTITY_STATUS_CHANGED';
    elsif old_row->'passport' is distinct from new_row->'passport' then
      event_name := 'CRYPTOGRAPHIC_PASSPORT_ROTATED';
    else
      return NEW;
    end if;
    subject := new_row->>'agent_id';
    event_data := jsonb_build_object(
      'org_id', new_row->>'org_id',
      'agent_id', new_row->>'agent_id',
      'did', new_row->>'did',
      'status', new_row->>'status'
    );
  elsif TG_TABLE_NAME = 'vgs_agent_identity_keys' then
    if TG_OP = 'INSERT' then
      event_name := 'AGENT_KEY_REGISTERED';
    elsif old_row->>'status' is distinct from new_row->>'status' then
      event_name := 'AGENT_KEY_STATUS_CHANGED';
    else
      return NEW;
    end if;
    subject := new_row->>'agent_id';
    event_data := jsonb_build_object(
      'org_id', new_row->>'org_id',
      'agent_id', new_row->>'agent_id',
      'key_id', new_row->>'key_id',
      'fingerprint', new_row->>'fingerprint',
      'status', new_row->>'status'
    );
  elsif TG_TABLE_NAME = 'vgs_agent_authority_commitments' then
    if TG_OP = 'INSERT' then
      event_name := 'AGENT_AUTHORITY_EVALUATED';
    elsif old_row->>'consumed_at' is null and new_row->>'consumed_at' is not null then
      event_name := 'AGENT_AUTHORITY_CONSUMED';
    elsif old_row->>'decision' is distinct from new_row->>'decision' then
      event_name := 'AGENT_AUTHORITY_DECISION_CHANGED';
    else
      return NEW;
    end if;
    subject := new_row->>'agent_id';
    event_data := jsonb_build_object(
      'org_id', new_row->>'org_id',
      'agent_id', new_row->>'agent_id',
      'commitment_id', new_row->>'commitment_id',
      'key_id', new_row->>'key_id',
      'action', new_row->>'action',
      'action_digest', new_row->>'action_digest',
      'decision', new_row->>'decision',
      'consumed', (new_row->>'consumed_at') is not null
    );
  else
    return NEW;
  end if;

  insert into public.vgs_proof_events (id, event_type, subject_id, data)
  values (gen_random_uuid()::text, event_name, subject, event_data);

  return NEW;
end;
$$;

revoke all on function public.vgs_write_agent_identity_proof_event()
  from public, anon, authenticated;
grant execute on function public.vgs_write_agent_identity_proof_event()
  to service_role;

drop trigger if exists vgs_agent_identity_proof_event on public.vgs_agent_identities;
create trigger vgs_agent_identity_proof_event
after insert or update on public.vgs_agent_identities
for each row execute function public.vgs_write_agent_identity_proof_event();

drop trigger if exists vgs_agent_identity_key_proof_event on public.vgs_agent_identity_keys;
create trigger vgs_agent_identity_key_proof_event
after insert or update on public.vgs_agent_identity_keys
for each row execute function public.vgs_write_agent_identity_proof_event();

drop trigger if exists vgs_agent_authority_proof_event on public.vgs_agent_authority_commitments;
create trigger vgs_agent_authority_proof_event
after insert or update on public.vgs_agent_authority_commitments
for each row execute function public.vgs_write_agent_identity_proof_event();

-- Fix the one legacy SECURITY DEFINER function found with a mutable public-only
-- search path. Its table references are already schema-qualified.
alter function public.vgs_consume_validation_receipt(text, text)
  set search_path = pg_catalog, public;
