-- 0008_vault.sql
-- Where secrets live. Provider API keys and per-account credentials go into
-- Supabase Vault, which encrypts them at rest. The application tables only ever
-- hold the NAME of a vault secret, never the secret itself.
--
-- The two functions below are the only doors into the Vault, and neither is
-- granted to `authenticated`. A logged-in browser session cannot call them at all,
-- so a credential cannot be read out through the public API even by an admin.

do $$
begin
  create extension if not exists supabase_vault with schema vault;
exception when others then
  -- Plain Postgres (local test databases) has no supabase_vault extension.
  -- The test harness installs a clearly-labelled stand-in instead; see tests/db/helpers.
  raise notice 'supabase_vault not available: %', sqlerrm;
end $$;

-- The one place a Vault secret name is constructed, so the writer and the reader
-- can never disagree about it.
create or replace function app.credential_name_for(target_account_id uuid)
returns text
language sql
immutable
set search_path = ''
as $$
  select 'social_account_' || replace(target_account_id::text, '-', '');
$$;

revoke all on function app.credential_name_for(uuid) from public;

-- Stores a credential for one social account in the Vault and records only its
-- name on the row. Returns the reference, never the secret.
--
-- The secret's name is DERIVED from the account id and never accepted from a
-- caller. An earlier version let the caller pass a name, which meant a tenant
-- could point their own row at another tenant's secret (or at a platform-wide
-- provider key) and have the publisher use it on their behalf.
create or replace function app.store_account_credential(
  target_account_id uuid,
  credential        text
)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  secret_name     text;
  existing_id     uuid;
  target_business uuid;
  is_rotation     boolean;
begin
  -- Refuse an id that is not a real social account. Without this a typo silently
  -- writes a credential into the Vault attached to nothing, and the UPDATE below
  -- matches no row, so the audit trigger never fires and nothing is recorded.
  select business_id into target_business
    from public.social_accounts where id = target_account_id;
  if target_business is null then
    raise exception 'no such social account: %', target_account_id
      using errcode = 'no_data_found';
  end if;

  secret_name := app.credential_name_for(target_account_id);

  select id into existing_id from vault.secrets where name = secret_name;

  if existing_id is null then
    perform vault.create_secret(credential, secret_name,
                                'PostDeck credential for social account ' || target_account_id);
  else
    perform vault.update_secret(existing_id, credential);
  end if;

  is_rotation := exists (
    select 1 from public.social_accounts
    where id = target_account_id and encrypted_credential_ref = secret_name
  );

  update public.social_accounts
     set encrypted_credential_ref = secret_name
   where id = target_account_id;

  -- Audited explicitly rather than left to the row trigger. Rotating a credential
  -- changes no column on the row, so the trigger would record
  -- `changed_columns: []` -- a permanent record saying nothing happened, for the
  -- single most sensitive operation in the system.
  perform app.write_audit(
    p_action      => case when is_rotation
                          then 'social_account.credential.rotated'
                          else 'social_account.credential.stored' end,
    p_business_id => target_business,
    p_target_type => 'social_accounts',
    p_target_id   => target_account_id::text,
    p_metadata    => jsonb_build_object('secret_name', secret_name)
  );

  return secret_name;
end;
$$;

-- Reads a credential back out of the Vault, for one social account.
--
-- Takes the ACCOUNT ID, not a secret name, and derives the name itself. This is
-- the important detail: the row's encrypted_credential_ref column is never used
-- to look the secret up, so retargeting that column buys an attacker nothing.
create or replace function app.read_account_credential(target_account_id uuid)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  plaintext   text;
  secret_name text;
begin
  -- Refuse an id that is not actually a social account.
  if not exists (select 1 from public.social_accounts where id = target_account_id) then
    raise exception 'no such social account: %', target_account_id
      using errcode = 'no_data_found';
  end if;

  secret_name := app.credential_name_for(target_account_id);

  select decrypted_secret into plaintext
    from vault.decrypted_secrets
   where name = secret_name;
  return plaintext;
end;
$$;

-- The important lines in this file. `authenticated` and `anon` are never granted
-- execute, so no browser session can reach a credential through PostgREST.
revoke all on function app.store_account_credential(uuid, text) from public;
revoke all on function app.read_account_credential(uuid)        from public;
grant execute on function app.store_account_credential(uuid, text) to service_role;
grant execute on function app.read_account_credential(uuid)        to service_role;
