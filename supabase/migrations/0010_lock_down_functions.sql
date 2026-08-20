-- 0010_lock_down_functions.sql
-- The last word on who may execute what.
--
-- This runs after every function exists, takes execute away from everyone, and
-- hands back exactly the four that a signed-in browser session needs. Doing it in
-- one place at the end means a function added by a future migration is locked by
-- default: it will simply not be callable until someone adds a line here, which is
-- a conversation rather than an accident.
--
-- Postgres grants EXECUTE to PUBLIC on every function it creates, so without this
-- every SECURITY DEFINER helper is an RLS bypass from the moment it exists.

revoke execute on all functions in schema app from public, anon, authenticated;

-- The only four a browser session may call. Each is a yes/no question about the
-- caller's own access, and each checks MFA internally.
grant execute on function app.has_completed_mfa()                                  to authenticated;
grant execute on function app.is_member_of(uuid)                                   to authenticated;
grant execute on function app.has_role_in(uuid, public.member_role[])              to authenticated;
grant execute on function app.post_belongs_to(uuid, uuid)                          to authenticated;
grant execute on function app.account_belongs_to(uuid, uuid)                       to authenticated;

-- Server-side only. `authenticated` and `anon` are never granted these.
grant execute on function app.write_audit(text, uuid, text, text, jsonb, inet, uuid) to service_role;
grant execute on function app.store_account_credential(uuid, text)                   to service_role;
grant execute on function app.read_account_credential(uuid)                          to service_role;
grant execute on function app.grant_admin_all_businesses(text)                       to service_role;

-- `anon` is granted nothing at all, in any schema, ever.
revoke all on schema app from anon;

-- And the same rule for functions that do not exist yet, so a helper added by a
-- future migration is locked from the moment it is created rather than from the
-- moment someone remembers to lock it.
--
-- This statement has two sharp edges, both deliberate:
--
--   It must NOT carry an `in schema` clause. Postgres accepts
--   `alter default privileges in schema app revoke execute on functions from public`,
--   reports success, writes nothing and changes nothing -- a silent no-op, because
--   the built-in PUBLIC EXECUTE default is global.
--
--   Being unqualified, it applies to every schema, so a `create extension` that
--   installs into `public` produces a type whose operators raise "permission
--   denied" for authenticated. Extensions therefore go in their own schema, which
--   is Supabase's own convention, and execute is granted there explicitly.
--
-- It is also recorded against the role that runs it, so a function created by a
-- different role is not covered. The class test in tests/db/hardening.test.ts is
-- what catches that, and it checks anon, authenticated and PUBLIC.
create schema if not exists extensions;
grant usage on schema extensions to authenticated, service_role;

alter default privileges revoke execute on functions from public;

-- Anything already installed into `extensions` stays callable.
--
-- Deliberately an explicit grant over what exists NOW, not a default privilege for
-- whatever arrives later. A standing `alter default privileges in schema extensions
-- grant execute on functions to authenticated` would mean a future
-- `create extension dblink with schema extensions` handed every one of its
-- functions to every signed-in user automatically -- and because the function class
-- test exempts extension-owned functions, that grant would also be exempt from the
-- check by construction. Auto-granted plus auto-exempt is not a combination to
-- leave armed for a later phase. A new extension now needs a grant someone wrote.
grant execute on all functions in schema extensions to authenticated, service_role;
