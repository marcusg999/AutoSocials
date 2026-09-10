-- Disconnecting an account must remove its credential, not just unlink the row.
--
-- Without this, a disconnected account leaves a live provider token sitting in the
-- Vault forever -- exactly the thing the operator believed they had revoked. The
-- row is kept (its audit history refers to it); the secret is not.

create or replace function app.delete_account_credential(target_account_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  secret_name     text;
  target_business uuid;
begin
  -- Same guard as store_account_credential: an id that is not a real account is a
  -- caller mistake, and silently succeeding would hide it.
  select business_id into target_business
    from public.social_accounts where id = target_account_id;
  if target_business is null then
    raise exception 'no such social account: %', target_account_id
      using errcode = 'no_data_found';
  end if;

  -- The name is DERIVED from the account id, never read from the row. That is the
  -- same rule the read path follows: the stored reference is not a lookup key, so
  -- a caller holding one cannot aim this at somebody else's secret.
  secret_name := app.credential_name_for(target_account_id);
  delete from vault.secrets where name = secret_name;

  perform app.write_audit(
    'connector.credential.deleted', target_business,
    'social_account', target_account_id::text, '{}'::jsonb, null, null);
end;
$$;

-- service_role only. A browser session must never reach the Vault, in any direction.
revoke all on function app.delete_account_credential(uuid) from public, anon, authenticated;
grant execute on function app.delete_account_credential(uuid) to service_role;
