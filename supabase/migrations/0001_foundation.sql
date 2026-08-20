-- 0001_foundation.sql
-- Creates the private `app` schema that holds our security helper functions.
-- Nothing in here is business data; it is the plumbing the RLS policies stand on.

-- Deliberately no extensions. pgcrypto used to be created here, which put ~36
-- functions into `public` -- a schema PostgREST exposes as RPC -- every one of them
-- executable by the signed-out `anon` role. public.crypt() with a high bcrypt cost
-- is a one-second-per-call CPU sink reachable without authentication.
--
-- Nothing here needs it: gen_random_uuid() has been core since PostgreSQL 13. If a
-- later phase does need pgcrypto, install it into its own schema
-- (`create extension pgcrypto with schema extensions`), never into public.

-- The `app` schema holds helper functions used by RLS policies.
-- It is deliberately NOT exposed to PostgREST, so clients can never call these directly.
create schema if not exists app;

revoke all on schema app from public;
grant usage on schema app to authenticated, service_role;

-- Returns true when the signed-in user has completed two-factor authentication.
--
-- Supabase stamps an "aal" (Authenticator Assurance Level) claim into the JWT:
--   aal1 = password only, aal2 = password + TOTP.
-- Reading it from the JWT means the database itself can refuse aal1 sessions,
-- so a bug in the web app can never expose tenant data to a half-authenticated user.
create or replace function app.has_completed_mfa()
returns boolean
language sql
stable
-- Locked search_path: stops anyone from shadowing `auth.jwt` with their own function.
set search_path = ''
as $$
  select coalesce(auth.jwt() ->> 'aal', 'aal1') = 'aal2';
$$;

comment on function app.has_completed_mfa() is
  'True only when the current JWT was issued after a TOTP challenge (aal2).';

revoke all on function app.has_completed_mfa() from public;
grant execute on function app.has_completed_mfa() to authenticated;
