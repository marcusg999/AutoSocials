-- ===========================================================================
-- TEST DOUBLE -- NEVER RUN THIS AGAINST A REAL DATABASE.
--
-- Supabase provides auth.users, auth.uid(), auth.jwt(), the anon/authenticated/
-- service_role roles and the Vault. A plain Postgres has none of them, so this
-- file recreates just enough of that surface for the RLS tests to run against a
-- real Postgres engine rather than a mock.
--
-- The definitions of auth.uid()/auth.jwt() below are the same ones Supabase uses:
-- they read the request.jwt.claims GUC. That is what makes these tests meaningful.
-- ===========================================================================

-- Supabase installs extensions into their own schema, never into `public`, because
-- `public` is exposed by PostgREST as RPC and every extension function would then
-- be callable by the signed-out `anon` role. Mirrored here so the test database is
-- not friendlier than production -- pgcrypto's crypt() at a high bcrypt cost is a
-- one-second-per-call CPU sink, reachable without authentication.
create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;
revoke all on schema extensions from public, anon, authenticated;

do $$ begin create role anon           nologin; exception when duplicate_object then null; end $$;
do $$ begin create role authenticated  nologin; exception when duplicate_object then null; end $$;
do $$ begin create role service_role   nologin bypassrls; exception when duplicate_object then null; end $$;

create schema if not exists auth;
grant usage on schema auth to anon, authenticated, service_role;

-- The other schemas a real Supabase project ships with.
--
-- These existed nowhere in the test harness, so the class tests' schema exclusion
-- list named schemas that were never present -- meaning the exclusion was never
-- exercised by a single test. On a real project `authenticated` already holds USAGE
-- on `storage`, so a business-scoped table created there is reachable, and a
-- migration that put one there produced a live cross-tenant read while the whole
-- suite stayed green. Modelled here so that attack can be represented at all.
create schema if not exists storage;
create schema if not exists realtime;
create schema if not exists graphql;
create schema if not exists graphql_public;
grant usage on schema storage to anon, authenticated, service_role;

create table if not exists auth.users (
  id    uuid primary key default gen_random_uuid(),
  email text unique
);

-- Identical to Supabase: the current user id, read from the request's JWT claims.
create or replace function auth.uid() returns uuid
language sql stable as $$
  select nullif(current_setting('request.jwt.claims', true)::jsonb ->> 'sub', '')::uuid;
$$;

-- Identical to Supabase: the whole decoded JWT, including the "aal" claim.
create or replace function auth.jwt() returns jsonb
language sql stable as $$
  select coalesce(nullif(current_setting('request.jwt.claims', true), '')::jsonb, '{}'::jsonb);
$$;

grant execute on function auth.uid(), auth.jwt() to anon, authenticated, service_role;

-- Minimal stand-in for Supabase Vault. Stores secrets encrypted with pgcrypto so
-- the tests exercise the same call shape; it is NOT the production Vault.
create schema if not exists vault;

create table if not exists vault.secrets (
  id          uuid primary key default gen_random_uuid(),
  name        text unique,
  description text default '',
  secret      text not null,
  created_at  timestamptz default now()
);

create or replace function vault.create_secret(new_secret text, new_name text default null, new_description text default '')
returns uuid language sql set search_path = extensions, vault, public as $$
  insert into vault.secrets (name, description, secret)
  values (new_name, new_description, extensions.pgp_sym_encrypt(new_secret, 'test-shim-key')::text)
  returning id;
$$;

create or replace function vault.update_secret(secret_id uuid, new_secret text default null, new_name text default null, new_description text default null)
returns void language sql set search_path = extensions, vault, public as $$
  update vault.secrets
     set secret = coalesce(extensions.pgp_sym_encrypt(new_secret, 'test-shim-key')::text, secret),
         name = coalesce(new_name, name),
         description = coalesce(new_description, description)
   where id = secret_id;
$$;

create or replace view vault.decrypted_secrets as
  select id, name, description, secret,
         extensions.pgp_sym_decrypt(secret::bytea, 'test-shim-key') as decrypted_secret
    from vault.secrets;

-- Mirrors Supabase: the Vault is not reachable from client roles.
revoke all on schema vault from anon, authenticated;

-- ===========================================================================
-- The single most important line in this file.
--
-- A real Supabase project runs this at bootstrap, which means EVERY table a
-- migration creates in `public` is automatically granted ALL privileges -- select,
-- insert, update, delete and TRUNCATE -- to the signed-out `anon` role. A test
-- database without it is far friendlier than production, and would happily certify
-- an app that a signed-out visitor could truncate.
--
-- Reproducing it here is what makes the "anon can touch nothing" tests meaningful:
-- they now pass only because 0006_rls_policies.sql explicitly revokes first.
-- ===========================================================================
alter default privileges in schema public
  grant all on tables to anon, authenticated, service_role;
alter default privileges in schema public
  grant all on sequences to anon, authenticated, service_role;
grant usage on schema public to anon, authenticated, service_role;
