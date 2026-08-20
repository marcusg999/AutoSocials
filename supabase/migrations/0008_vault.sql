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

-- Stores a credential for one social account in the Vault and records only its
-- name on the row. Returns the reference, never the secret.
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
  secret_name text;
  existing_id uuid;
begin
  -- A stable, non-guessable name derived from the account id.
  secret_name := 'social_account_' || replace(target_account_id::text, '-', '');

  select id into existing_id from vault.secrets where name = secret_name;

  if existing_id is null then
    perform vault.create_secret(credential, secret_name,
                                'PostDeck credential for social account ' || target_account_id);
  else
    perform vault.update_secret(existing_id, credential);
  end if;

  update public.social_accounts
     set encrypted_credential_ref = secret_name
   where id = target_account_id;

  return secret_name;
end;
$$;

-- Reads a credential back out of the Vault. Server-side callers only.
create or replace function app.read_account_credential(secret_name text)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  plaintext text;
begin
  select decrypted_secret into plaintext
    from vault.decrypted_secrets
   where name = secret_name;
  return plaintext;
end;
$$;

-- The important lines in this file. `authenticated` and `anon` are never granted
-- execute, so no browser session can reach a credential through PostgREST.
revoke all on function app.store_account_credential(uuid, text) from public;
revoke all on function app.read_account_credential(text)        from public;
grant execute on function app.store_account_credential(uuid, text) to service_role;
grant execute on function app.read_account_credential(text)        to service_role;
