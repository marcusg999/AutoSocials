alter table public.social_accounts
  drop column if exists token_expires_at,
  drop column if exists scopes;
