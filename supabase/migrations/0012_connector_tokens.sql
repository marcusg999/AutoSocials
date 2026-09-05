-- Phase 2: the connector layer needs two more facts per connected account.
--
-- Both are non-secret. The credential itself stays in Supabase Vault, reachable
-- only through app.read_account_credential(account_id), which derives the secret
-- name from the id -- so the stored reference is never a lookup key. Nothing here
-- changes that.

alter table public.social_accounts
  -- When the stored token stops working. Meta's long-lived page tokens last about
  -- 60 days, so the app has to know when to ask for a reconnect rather than
  -- discovering it from a failed publish in a later phase.
  add column if not exists token_expires_at timestamptz,
  -- What the user actually granted. Meta returns the granted scopes, which can be
  -- fewer than the ones requested, and a later phase must not assume it can post.
  add column if not exists scopes text[] not null default '{}';

-- The app may read these and set them through the same column-level grant the
-- other non-secret columns use. encrypted_credential_ref is still excluded.
grant update (token_expires_at, scopes) on public.social_accounts to authenticated;
grant insert (token_expires_at, scopes) on public.social_accounts to authenticated;
