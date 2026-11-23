-- Cryptographic Passport identity and runtime-authority layer.
-- STAGING ONLY: review and apply this migration to the isolated staging Supabase
-- project before enabling these routes. Never apply to production as part of this PR.

create table if not exists public.vgs_agent_identity_memberships (
  membership_id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  org_id uuid not null,
  role text not null check (role in ('owner','admin','operator','auditor')),
  status text not null default 'ACTIVE' check (status in ('ACTIVE','SUSPENDED','REVOKED')),
  created_at timestamptz not null default now(),
  unique (user_id, org_id)
);

create table if not exists public.vgs_agent_identity_api_keys (
  key_id uuid primary key,
  org_id uuid not null,
  key_hash text not null unique,
  key_prefix text not null,
  name text not null,
  scopes jsonb not null,
  status text not null default 'ACTIVE' check (status in ('ACTIVE','REVOKED')),
  created_by uuid not null,
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  revoked_at timestamptz
);

create table if not exists public.vgs_agent_identities (
  agent_id uuid primary key,
  org_id uuid not null,
  agent_name text not null,
  did text not null unique,
  passport jsonb not null,
  capabilities jsonb not null,
  status text not null default 'ACTIVE' check (status in ('ACTIVE','REVOKED')),
  issued_at timestamptz not null,
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.vgs_agent_identity_keys (
  key_id text not null,
  org_id uuid not null,
  agent_id uuid not null references public.vgs_agent_identities(agent_id),
  public_key_b64 text not null,
  fingerprint text not null,
  algorithm text not null check (algorithm = 'Ed25519'),
  status text not null default 'ACTIVE' check (status in ('ACTIVE','ROTATED','REVOKED')),
  created_at timestamptz not null default now(),
  revoked_at timestamptz,
  primary key (org_id, key_id),
  unique (org_id, agent_id, fingerprint)
);

create table if not exists public.vgs_agent_identity_challenges (
  challenge_id uuid primary key,
  org_id uuid not null,
  purpose text not null check (purpose in ('REGISTER_AGENT','ROTATE_KEY')),
  agent_id uuid,
  key_fingerprint text not null,
  nonce text not null,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.vgs_agent_delegations (
  delegation_id uuid primary key,
  org_id uuid not null,
  grantor_agent_id uuid not null references public.vgs_agent_identities(agent_id),
  grantee_agent_id uuid not null references public.vgs_agent_identities(agent_id),
  scopes jsonb not null,
  status text not null default 'ACTIVE' check (status in ('ACTIVE','REVOKED')),
  issued_at timestamptz not null,
  expires_at timestamptz not null,
  revoked_at timestamptz,
  check (grantor_agent_id <> grantee_agent_id)
);

create table if not exists public.vgs_agent_authority_commitments (
  commitment_id uuid primary key,
  org_id uuid not null,
  agent_id uuid not null references public.vgs_agent_identities(agent_id),
  key_id text not null,
  delegation_id uuid references public.vgs_agent_delegations(delegation_id),
  action text not null,
  action_digest text not null,
  parameters jsonb not null,
  decision text not null check (decision in ('AUTHORIZED','REFUSED')),
  reasons jsonb not null default '[]'::jsonb,
  decision_receipt jsonb not null,
  consumption_receipt jsonb,
  evaluated_at timestamptz not null default now(),
  expires_at timestamptz not null,
  consumed_at timestamptz,
  foreign key (org_id, key_id)
    references public.vgs_agent_identity_keys(org_id, key_id)
);

create index if not exists vgs_agent_identity_org_idx
  on public.vgs_agent_identities(org_id, created_at desc);
create index if not exists vgs_agent_keys_agent_idx
  on public.vgs_agent_identity_keys(org_id, agent_id, status);
create index if not exists vgs_agent_delegations_grantee_idx
  on public.vgs_agent_delegations(org_id, grantee_agent_id, status, expires_at);
create index if not exists vgs_agent_commitments_org_idx
  on public.vgs_agent_authority_commitments(org_id, commitment_id);
create index if not exists vgs_agent_challenges_expiry_idx
  on public.vgs_agent_identity_challenges(expires_at) where consumed_at is null;

-- Service-role-only access. Tenant isolation is enforced in every API query and
-- in the atomic consume function; client JWTs never receive direct table grants.
do $$
declare t text;
begin
  foreach t in array array[
    'vgs_agent_identity_memberships','vgs_agent_identity_api_keys',
    'vgs_agent_identities','vgs_agent_identity_keys',
    'vgs_agent_identity_challenges','vgs_agent_delegations',
    'vgs_agent_authority_commitments'
  ] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('revoke all on public.%I from anon, authenticated', t);
    execute format('grant select, insert, update, delete on public.%I to service_role', t);
  end loop;
end $$;

create or replace function public.vgs_consume_agent_identity_challenge(
  p_challenge_id uuid, p_org_id uuid, p_purpose text, p_key_fingerprint text
) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public
as $$
declare consumed jsonb;
begin
  update public.vgs_agent_identity_challenges c
     set consumed_at = clock_timestamp()
   where c.challenge_id = p_challenge_id
     and c.org_id = p_org_id
     and c.purpose = p_purpose
     and c.key_fingerprint = p_key_fingerprint
     and c.consumed_at is null
     and c.expires_at > clock_timestamp()
  returning to_jsonb(c) into consumed;
  return consumed;
end;
$$;

create or replace function public.vgs_create_agent_identity(
  p_agent jsonb, p_key jsonb
) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public
as $$
declare a jsonb; k jsonb;
begin
  if (p_agent->>'org_id')::uuid <> (p_key->>'org_id')::uuid
     or (p_agent->>'agent_id')::uuid <> (p_key->>'agent_id')::uuid then
    raise exception 'Agent and key tenant/identity binding mismatch';
  end if;

  insert into public.vgs_agent_identities as inserted
    (agent_id, org_id, agent_name, did, passport, capabilities, status, issued_at, expires_at)
  values
    ((p_agent->>'agent_id')::uuid, (p_agent->>'org_id')::uuid,
     p_agent->>'agent_name', p_agent->>'did', p_agent->'passport',
     p_agent->'capabilities', p_agent->>'status',
     (p_agent->>'issued_at')::timestamptz, (p_agent->>'expires_at')::timestamptz)
  returning to_jsonb(inserted) into a;

  insert into public.vgs_agent_identity_keys as inserted
    (key_id, org_id, agent_id, public_key_b64, fingerprint, algorithm, status)
  values
    (p_key->>'key_id', (p_key->>'org_id')::uuid, (p_key->>'agent_id')::uuid,
     p_key->>'public_key_b64', p_key->>'fingerprint',
     p_key->>'algorithm', p_key->>'status')
  returning to_jsonb(inserted) into k;

  return jsonb_build_object('agent', a, 'key', k);
end;
$$;

create or replace function public.vgs_rotate_agent_identity_key(
  p_org_id uuid, p_agent_id uuid, p_key jsonb, p_passport jsonb,
  p_replace_existing boolean default true
) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public
as $$
declare a jsonb; k jsonb;
begin
  update public.vgs_agent_identities as target
     set passport = p_passport, updated_at = clock_timestamp()
   where org_id = p_org_id and agent_id = p_agent_id and status = 'ACTIVE'
     and expires_at > clock_timestamp()
  returning to_jsonb(target) into a;
  if a is null then return null; end if;

  if p_replace_existing then
    update public.vgs_agent_identity_keys as target
       set status = 'ROTATED', revoked_at = clock_timestamp()
     where org_id = p_org_id and agent_id = p_agent_id and status = 'ACTIVE';
  end if;

  insert into public.vgs_agent_identity_keys as inserted
    (key_id, org_id, agent_id, public_key_b64, fingerprint, algorithm, status)
  values
    (p_key->>'key_id', p_org_id, p_agent_id, p_key->>'public_key_b64',
     p_key->>'fingerprint', 'Ed25519', 'ACTIVE')
  returning to_jsonb(inserted) into k;

  return jsonb_build_object('agent', a, 'key', k);
end;
$$;

create or replace function public.vgs_revoke_agent_identity(
  p_org_id uuid, p_agent_id uuid
) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public
as $$
declare key_count integer; delegation_count integer;
begin
  update public.vgs_agent_identities
     set status = 'REVOKED', updated_at = clock_timestamp()
   where org_id = p_org_id and agent_id = p_agent_id and status <> 'REVOKED';

  update public.vgs_agent_identity_keys
     set status = 'REVOKED', revoked_at = clock_timestamp()
   where org_id = p_org_id and agent_id = p_agent_id and status = 'ACTIVE';
  get diagnostics key_count = row_count;

  update public.vgs_agent_delegations
     set status = 'REVOKED', revoked_at = clock_timestamp()
   where org_id = p_org_id and status = 'ACTIVE'
     and (grantor_agent_id = p_agent_id or grantee_agent_id = p_agent_id);
  get diagnostics delegation_count = row_count;

  update public.vgs_agent_authority_commitments
     set decision = 'REFUSED', reasons = jsonb_build_array('AGENT_REVOKED')
   where org_id = p_org_id and agent_id = p_agent_id
     and consumed_at is null and decision = 'AUTHORIZED';

  return jsonb_build_object('agent_id', p_agent_id,
    'revoked_keys', key_count, 'revoked_delegations', delegation_count);
end;
$$;

drop function if exists public.vgs_consume_agent_authority_commitment(uuid,uuid,text);

create or replace function public.vgs_consume_agent_authority_commitment(
  p_commitment_id uuid, p_org_id uuid, p_action_digest text,
  p_consumed_at timestamptz, p_consumption_receipt jsonb
) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public
as $$
declare
  c public.vgs_agent_authority_commitments%rowtype;
  a public.vgs_agent_identities%rowtype;
  g public.vgs_agent_identities%rowtype;
  k public.vgs_agent_identity_keys%rowtype;
  d public.vgs_agent_delegations%rowtype;
  consumed jsonb;
begin
  -- Read immutable identifiers first, then acquire locks in the same order as
  -- revocation/rotation: agents -> key -> delegation -> commitment.
  select * into c
    from public.vgs_agent_authority_commitments
   where commitment_id = p_commitment_id and org_id = p_org_id;
  if not found then return null; end if;

  perform 1
    from public.vgs_agent_identities ai
   where ai.org_id = p_org_id
     and (
       ai.agent_id = c.agent_id
       or (
         c.delegation_id is not null
         and ai.agent_id = (
           select grantor_agent_id from public.vgs_agent_delegations
            where delegation_id = c.delegation_id and org_id = p_org_id
         )
       )
     )
   order by ai.agent_id
   for update;

  perform 1
    from public.vgs_agent_identity_keys ak
   where ak.org_id = p_org_id and ak.agent_id = c.agent_id and ak.key_id = c.key_id
   for update;

  if c.delegation_id is not null then
    perform 1
      from public.vgs_agent_delegations ad
     where ad.org_id = p_org_id and ad.delegation_id = c.delegation_id
     for update;
  end if;

  select * into c
    from public.vgs_agent_authority_commitments
   where commitment_id = p_commitment_id and org_id = p_org_id
   for update;

  if not found
     or c.action_digest <> p_action_digest
     or c.decision <> 'AUTHORIZED'
     or c.consumed_at is not null
     or c.expires_at <= clock_timestamp() then
    return null;
  end if;

  select * into a
    from public.vgs_agent_identities
   where org_id = p_org_id and agent_id = c.agent_id;
  if not found or a.status <> 'ACTIVE' or a.expires_at <= clock_timestamp() then
    return null;
  end if;

  select * into k
    from public.vgs_agent_identity_keys
   where org_id = p_org_id and agent_id = c.agent_id and key_id = c.key_id;
  if not found or k.status <> 'ACTIVE' or k.fingerprint <> k.key_id then
    return null;
  end if;

  if c.delegation_id is null then
    if not (a.capabilities ? c.action) then return null; end if;
  else
    select * into d
      from public.vgs_agent_delegations
     where org_id = p_org_id and delegation_id = c.delegation_id;
    if not found
       or d.status <> 'ACTIVE'
       or d.expires_at <= clock_timestamp()
       or d.grantee_agent_id <> c.agent_id
       or not (d.scopes ? c.action) then
      return null;
    end if;

    select * into g
      from public.vgs_agent_identities
     where org_id = p_org_id and agent_id = d.grantor_agent_id;
    if not found
       or g.status <> 'ACTIVE'
       or g.expires_at <= clock_timestamp()
       or not (g.capabilities ? c.action) then
      return null;
    end if;
  end if;

  update public.vgs_agent_authority_commitments as target
     set consumed_at = p_consumed_at,
         consumption_receipt = p_consumption_receipt
   where commitment_id = p_commitment_id
     and org_id = p_org_id
     and consumed_at is null
  returning to_jsonb(target) into consumed;

  return consumed;
end;
$$;

revoke all on function public.vgs_consume_agent_identity_challenge(uuid,uuid,text,text) from public, anon, authenticated;
revoke all on function public.vgs_create_agent_identity(jsonb,jsonb) from public, anon, authenticated;
revoke all on function public.vgs_rotate_agent_identity_key(uuid,uuid,jsonb,jsonb,boolean) from public, anon, authenticated;
revoke all on function public.vgs_revoke_agent_identity(uuid,uuid) from public, anon, authenticated;
revoke all on function public.vgs_consume_agent_authority_commitment(uuid,uuid,text,timestamptz,jsonb) from public, anon, authenticated;
grant execute on function public.vgs_consume_agent_identity_challenge(uuid,uuid,text,text) to service_role;
grant execute on function public.vgs_create_agent_identity(jsonb,jsonb) to service_role;
grant execute on function public.vgs_rotate_agent_identity_key(uuid,uuid,jsonb,jsonb,boolean) to service_role;
grant execute on function public.vgs_revoke_agent_identity(uuid,uuid) to service_role;
grant execute on function public.vgs_consume_agent_authority_commitment(uuid,uuid,text,timestamptz,jsonb) to service_role;

-- Bootstrap tenant owner after creating the organisation and inviting the user:
-- insert into public.vgs_agent_identity_memberships(user_id, org_id, role)
-- values ('<auth.users UUID>', '<tenant UUID>', 'owner');
-- Never insert an unverified user id supplied by a client request.
