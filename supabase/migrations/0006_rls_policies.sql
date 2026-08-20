-- 0006_rls_policies.sql
-- Every policy below is preceded by one plain-English sentence describing it.
--
-- Two kinds of policy are used:
--   PERMISSIVE (the default) grants access -- a row is visible if ANY of them passes.
--   RESTRICTIVE narrows access -- EVERY one of them must pass, no matter what.
-- Tenant membership is permissive. The MFA requirement is restrictive, so it can
-- never be widened by adding another policy later.

-- Table privileges first. RLS filters rows, but Postgres still needs the plain
-- GRANT before a role may touch the table at all.
--
-- START BY TAKING EVERYTHING AWAY. This is not paranoia: a Supabase project ships
-- with `alter default privileges in schema public grant all on tables to anon,
-- authenticated, service_role`, so every table these migrations create is
-- automatically granted ALL -- including TRUNCATE -- to the signed-out `anon`
-- role. RLS does not filter TRUNCATE and TRUNCATE fires no row triggers, so
-- without these two lines a signed-out role could empty every table, audit log
-- included, leaving no trace. Revoke first, then grant back only what is needed.
revoke all on all tables    in schema public from anon, authenticated;
revoke all on all sequences in schema public from anon, authenticated;

-- And cancel the rule going forward, not just for the tables that exist right now.
-- Without these two lines the very next migration anyone writes creates a table
-- that is once again fully granted to `anon`, TRUNCATE included, and the hole
-- above reopens silently.
alter default privileges in schema public revoke all on tables    from anon, authenticated;
alter default privileges in schema public revoke all on sequences from anon, authenticated;

-- Function privileges are NOT handled here. Two approaches were tried and both
-- were wrong, so the reasoning is recorded rather than repeated:
--
--   `alter default privileges in schema app revoke execute on functions from public`
--     is a silent no-op. Postgres accepts it, reports success, writes no
--     pg_default_acl row and changes nothing, because the built-in PUBLIC EXECUTE
--     default is global and a schema-scoped revoke has nothing to subtract.
--
--   the same statement without `in schema` does work, but it applies to EVERY
--     schema and is recorded against one role. A function created by any other
--     role reopens the hole, and -- worse -- every future `create extension`
--     installs a type whose operators raise "permission denied" for authenticated.
--     Verified with citext: `'ABC'::citext = 'abc'::citext` failed outright.
--
-- Instead, 0010_lock_down_functions.sql revokes explicitly across schema `app`
-- after every function exists, and re-grants exactly the four the app needs.

-- `anon` is granted nothing at all: a signed-out visitor cannot touch any table.
grant select                          on public.businesses        to authenticated;

-- businesses is granted UPDATE column by column. A table-wide grant let an owner
-- rewrite created_by -- forging provenance, and turning the foreign key into a
-- platform-wide "does this user exist?" probe -- and rewrite created_at.
grant update (name, timezone)         on public.businesses        to authenticated;
-- SELECT only. Adding a member takes a user id from the caller, and `user_id` is a
-- foreign key into auth.users -- a table nobody can read -- so an INSERT turned the
-- error message into a platform-wide "does this account exist?" probe, and a
-- successful one attached a real person to a business without their consent. Phase 1
-- has a single administrator and manages membership from the seed script under
-- service_role, so the app needs no write access at all.
grant select                          on public.business_members  to authenticated;
grant select, delete                 on public.social_accounts   to authenticated;
grant select, insert, delete          on public.posts             to authenticated;

-- posts is granted UPDATE column by column, excluding created_by: authorship is
-- set once, at insert, and is never editable afterwards.
grant update (status, body)           on public.posts             to authenticated;
grant select, insert, update, delete on public.scheduled_posts   to authenticated;
grant select                          on public.audit_log        to authenticated;

-- social_accounts is granted INSERT and UPDATE column by column, deliberately
-- EXCLUDING encrypted_credential_ref from BOTH. That column names a secret in the
-- Vault; if a tenant could set it -- on a new row just as easily as on an existing
-- one -- they could point their own row at another tenant's secret and have the
-- publisher use it on their behalf. Only the server may set it, via
-- app.store_account_credential().
grant insert (business_id, platform, label, provider, provider_account_ref, status, connected_at)
  on public.social_accounts to authenticated;
grant update (label, provider, provider_account_ref, status, connected_at)
  on public.social_accounts to authenticated;

-- No sequence is granted to anyone. Every table here uses uuid primary keys except
-- audit_log, and burning ids from ITS sequence would punch gaps in an append-only
-- table -- where a gap is supposed to mean tampering.


-- ===========================================================================
-- MFA gate: applies to every table, for every command.
-- ===========================================================================

-- A signed-in user who has not passed a TOTP challenge sees and writes nothing, anywhere.
drop policy if exists mfa_required on public.businesses;
create policy mfa_required on public.businesses as restrictive for all to authenticated
  using (app.has_completed_mfa()) with check (app.has_completed_mfa());

-- A signed-in user who has not passed a TOTP challenge sees and writes nothing, anywhere.
drop policy if exists mfa_required on public.business_members;
create policy mfa_required on public.business_members as restrictive for all to authenticated
  using (app.has_completed_mfa()) with check (app.has_completed_mfa());

-- A signed-in user who has not passed a TOTP challenge sees and writes nothing, anywhere.
drop policy if exists mfa_required on public.social_accounts;
create policy mfa_required on public.social_accounts as restrictive for all to authenticated
  using (app.has_completed_mfa()) with check (app.has_completed_mfa());

-- A signed-in user who has not passed a TOTP challenge sees and writes nothing, anywhere.
drop policy if exists mfa_required on public.posts;
create policy mfa_required on public.posts as restrictive for all to authenticated
  using (app.has_completed_mfa()) with check (app.has_completed_mfa());

-- A signed-in user who has not passed a TOTP challenge sees and writes nothing, anywhere.
drop policy if exists mfa_required on public.scheduled_posts;
create policy mfa_required on public.scheduled_posts as restrictive for all to authenticated
  using (app.has_completed_mfa()) with check (app.has_completed_mfa());

-- A signed-in user who has not passed a TOTP challenge sees and writes nothing, anywhere.
drop policy if exists mfa_required on public.audit_log;
create policy mfa_required on public.audit_log as restrictive for all to authenticated
  using (app.has_completed_mfa()) with check (app.has_completed_mfa());


-- ===========================================================================
-- businesses
-- ===========================================================================

-- You can see a business only if you are one of its members.
drop policy if exists businesses_select_own on public.businesses;
create policy businesses_select_own on public.businesses for select to authenticated
  using (app.is_member_of(id));

-- Only an owner or manager of a business may rename it or change its timezone.
drop policy if exists businesses_update_by_manager on public.businesses;
create policy businesses_update_by_manager on public.businesses for update to authenticated
  using      (app.has_role_in(id, array['owner','manager']::public.member_role[]))
  with check (app.has_role_in(id, array['owner','manager']::public.member_role[]));

-- Nobody creates or deletes businesses from the app in Phase 1; they are seeded
-- by an administrator, so no INSERT or DELETE policy exists and both are denied.


-- ===========================================================================
-- business_members
--
-- Read-only from the application in Phase 1. Membership is granted by the seed
-- script under service_role; there are deliberately no INSERT, UPDATE or DELETE
-- policies, so all three are denied by default.
-- ===========================================================================

-- You can see the membership list of a business only if you are a member of it.
drop policy if exists members_select_own_business on public.business_members;
create policy members_select_own_business on public.business_members for select to authenticated
  using (app.is_member_of(business_id));





-- ===========================================================================
-- social_accounts
-- ===========================================================================

-- You can see a connected social account only if you are a member of the business that owns it.
drop policy if exists accounts_select_own_business on public.social_accounts;
create policy accounts_select_own_business on public.social_accounts for select to authenticated
  using (app.is_member_of(business_id));

-- Only an owner or manager may connect a social account, and only to their own business.
drop policy if exists accounts_insert_own_business on public.social_accounts;
create policy accounts_insert_own_business on public.social_accounts for insert to authenticated
  with check (app.has_role_in(business_id, array['owner','manager']::public.member_role[]));

-- Only an owner or manager may edit a social account, and they may not move it to another business.
drop policy if exists accounts_update_own_business on public.social_accounts;
create policy accounts_update_own_business on public.social_accounts for update to authenticated
  using      (app.has_role_in(business_id, array['owner','manager']::public.member_role[]))
  with check (app.has_role_in(business_id, array['owner','manager']::public.member_role[]));

-- Only an owner or manager may disconnect a social account.
drop policy if exists accounts_delete_own_business on public.social_accounts;
create policy accounts_delete_own_business on public.social_accounts for delete to authenticated
  using (app.has_role_in(business_id, array['owner','manager']::public.member_role[]));


-- ===========================================================================
-- posts
-- ===========================================================================

-- You can see a post only if you are a member of the business it belongs to.
drop policy if exists posts_select_own_business on public.posts;
create policy posts_select_own_business on public.posts for select to authenticated
  using (app.is_member_of(business_id));

-- Only an owner or manager may write a post, only in their own business, and only under their own name.
drop policy if exists posts_insert_own_business on public.posts;
create policy posts_insert_own_business on public.posts for insert to authenticated
  with check (
    app.has_role_in(business_id, array['owner','manager']::public.member_role[])
    -- created_by must be yourself. Otherwise you could stamp a post with a user id
    -- from another tenant, which both forges authorship and -- because created_by
    -- is a foreign key into auth.users -- turns the error message into a
    -- platform-wide "does this user exist?" oracle.
    and created_by = (select auth.uid())
  );

-- Only an owner or manager may edit a post, and only within their own business.
--
-- Authorship is not mentioned here on purpose. An earlier version required
-- `created_by = auth.uid()` on the NEW row, which meant a manager editing a
-- colleague's post had to reassign it to themselves for the update to pass -- the
-- exact opposite of what its comment claimed. created_by is now pinned by a
-- trigger and is not in the UPDATE grant at all, so it cannot change by any route.
drop policy if exists posts_update_own_business on public.posts;
create policy posts_update_own_business on public.posts for update to authenticated
  using      (app.has_role_in(business_id, array['owner','manager']::public.member_role[]))
  with check (app.has_role_in(business_id, array['owner','manager']::public.member_role[]));

-- Only an owner or manager may delete a post.
drop policy if exists posts_delete_own_business on public.posts;
create policy posts_delete_own_business on public.posts for delete to authenticated
  using (app.has_role_in(business_id, array['owner','manager']::public.member_role[]));


-- ===========================================================================
-- scheduled_posts
--
-- This table carries its own business_id, denormalized from the parent post so a
-- cascade delete stays attributable. Every write checks that the post AND the
-- target social account both sit in that same business -- otherwise you could aim
-- your own post at someone else's connected account.
-- ===========================================================================

-- You can see a scheduled post only if you are a member of the business it belongs to.
drop policy if exists scheduled_select_own_business on public.scheduled_posts;
create policy scheduled_select_own_business on public.scheduled_posts for select to authenticated
  using (app.is_member_of(business_id));

-- You may schedule a post only as an owner or manager, and only when the post and the target account both sit in that same business.
drop policy if exists scheduled_insert_own_business on public.scheduled_posts;
create policy scheduled_insert_own_business on public.scheduled_posts for insert to authenticated
  with check (
    app.has_role_in(business_id, array['owner','manager']::public.member_role[])
    and app.post_belongs_to(post_id, business_id)
    and app.account_belongs_to(social_account_id, business_id)
  );

-- You may change a scheduled post only as an owner or manager, and it must still point at that same business's post and account afterwards.
drop policy if exists scheduled_update_own_business on public.scheduled_posts;
create policy scheduled_update_own_business on public.scheduled_posts for update to authenticated
  using (app.has_role_in(business_id, array['owner','manager']::public.member_role[]))
  with check (
    app.has_role_in(business_id, array['owner','manager']::public.member_role[])
    and app.post_belongs_to(post_id, business_id)
    and app.account_belongs_to(social_account_id, business_id)
  );

-- Only an owner or manager may unschedule a post, and only in their own business.
drop policy if exists scheduled_delete_own_business on public.scheduled_posts;
create policy scheduled_delete_own_business on public.scheduled_posts for delete to authenticated
  using (app.has_role_in(business_id, array['owner','manager']::public.member_role[]));


-- ===========================================================================
-- audit_log
-- ===========================================================================

-- You can read an audit entry if it belongs to one of your businesses, or if it is about you.
drop policy if exists audit_select_own on public.audit_log;
create policy audit_select_own on public.audit_log for select to authenticated
  using (
    (business_id is not null and app.is_member_of(business_id))
    or actor_user_id = (select auth.uid())
  );

-- Nobody writes audit rows by hand: there is no INSERT, UPDATE or DELETE policy,
-- so the only way in is app.write_audit(), which stamps the actor from the JWT.
