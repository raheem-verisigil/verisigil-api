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
  key_id text primary key,
  org_id uuid not null,
  agent_id uuid not null references public.vgs_agent_identities(agent_id),
  public_key_b64 text not null,
  fingerprint text not null,
  algorithm text not null check (algorithm = 'Ed25519'),
  status text not null default 'ACTIVE' check (status in ('ACTIVE','ROTATED','REVOKED')),
  created_at timestamptz not null default now(),
  revoked_at timestamptz,
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
  key_id text not null references public.vgs_agent_identity_keys(key_id),
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
  consumed_at timestamptz
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
language plpgsql security definer set search_path = public
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
language plpgsql security definer set search_path = public
as $$
declare a jsonb; k jsonb;
begin
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
language plpgsql security definer set search_path = public
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
language plpgsql security definer set search_path = public
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

create or replace function public.vgs_consume_agent_authority_commitment(
  p_commitment_id uuid, p_org_id uuid, p_action_digest text
) returns jsonb
language plpgsql security definer set search_path = public
as $$
declare consumed jsonb;
begin
  -- A single guarded UPDATE and EXISTS predicates serialize consumption across replicas.
  update public.vgs_agent_authority_commitments c
     set consumed_at = clock_timestamp()
   where c.commitment_id = p_commitment_id
     and c.org_id = p_org_id
     and c.action_digest = p_action_digest
     and c.decision = 'AUTHORIZED'
     and c.consumed_at is null
     and c.expires_at > clock_timestamp()
     and exists (
       select 1 from public.vgs_agent_identities a
       join public.vgs_agent_identity_keys k
         on k.agent_id = a.agent_id and k.org_id = a.org_id
       where a.agent_id = c.agent_id and a.org_id = c.org_id
         and a.status = 'ACTIVE' and a.expires_at > clock_timestamp()
         and k.key_id = c.key_id and k.status = 'ACTIVE'
         and (
           (c.delegation_id is null and a.capabilities ? c.action)
           or
           (c.delegation_id is not null and exists (
             select 1
               from public.vgs_agent_delegations d
               join public.vgs_agent_identities g
                 on g.agent_id = d.grantor_agent_id and g.org_id = d.org_id
              where d.delegation_id = c.delegation_id
                and d.org_id = c.org_id
                and d.grantee_agent_id = c.agent_id
                and d.status = 'ACTIVE'
                and d.expires_at > clock_timestamp()
                and d.scopes ? c.action
                and g.status = 'ACTIVE'
                and g.expires_at > clock_timestamp()
                and g.capabilities ? c.action
           ))
         )
     )
  returning to_jsonb(c) into consumed;
  return consumed;
end;
$$;

revoke all on function public.vgs_consume_agent_identity_challenge(uuid,uuid,text,text) from public, anon, authenticated;
revoke all on function public.vgs_create_agent_identity(jsonb,jsonb) from public, anon, authenticated;
revoke all on function public.vgs_rotate_agent_identity_key(uuid,uuid,jsonb,jsonb,boolean) from public, anon, authenticated;
revoke all on function public.vgs_revoke_agent_identity(uuid,uuid) from public, anon, authenticated;
revoke all on function public.vgs_consume_agent_authority_commitment(uuid,uuid,text) from public, anon, authenticated;
grant execute on function public.vgs_consume_agent_identity_challenge(uuid,uuid,text,text) to service_role;
grant execute on function public.vgs_create_agent_identity(jsonb,jsonb) to service_role;
grant execute on function public.vgs_rotate_agent_identity_key(uuid,uuid,jsonb,jsonb,boolean) to service_role;
grant execute on function public.vgs_revoke_agent_identity(uuid,uuid) to service_role;
grant execute on function public.vgs_consume_agent_authority_commitment(uuid,uuid,text) to service_role;

-- Bootstrap tenant owner after creating the organisation and inviting the user:
-- insert into public.vgs_agent_identity_memberships(user_id, org_id, role)
-- values ('<auth.users UUID>', '<tenant UUID>', 'owner');
-- Never insert an unverified user id supplied by a client request.
