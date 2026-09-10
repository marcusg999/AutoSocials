-- 0005_rls_helpers.sql
-- The three questions every RLS policy in this app asks. They live here, after the
-- tables exist, because Postgres validates a SQL function body when you create it.

-- Returns true when the signed-in user belongs to the given business AND has
-- completed TOTP.
--
-- The MFA check is inside the function, not only in the RESTRICTIVE table policy.
-- These helpers are SECURITY DEFINER and granted to `authenticated`, so they are
-- reachable by anyone with a SQL channel whether or not they ever pass a table
-- policy. A helper that answers questions an aal1 session should not be able to
-- ask is a bypass of the MFA gate, however narrow.
--
-- SECURITY DEFINER on purpose. It reads business_members, and the business_members
-- policies themselves need to ask "is this user a member?" -- asking through RLS
-- would make the policy call itself forever. Running as the function owner steps
-- outside RLS and breaks that loop.
create or replace function app.is_member_of(target_business_id uuid)
returns boolean
language sql
stable
security definer
-- Locked search_path: a SECURITY DEFINER function without this is a privilege-escalation hole.
set search_path = ''
as $$
  select app.has_completed_mfa() and exists (
    select 1 from public.business_members m
    where m.business_id = target_business_id
      and m.user_id = (select auth.uid())
  );
$$;

-- Returns true when the signed-in user holds one of the given roles in the business.
create or replace function app.has_role_in(target_business_id uuid, allowed public.member_role[])
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select app.has_completed_mfa() and exists (
    select 1 from public.business_members m
    where m.business_id = target_business_id
      and m.user_id = (select auth.uid())
      and m.role = any(allowed)
  );
$$;

-- Answers "does this post sit in this business?" -- used to keep all three ids on a
-- scheduled_posts row pointing at the same tenant.
--
-- Note it takes the business as an ARGUMENT and returns a boolean, rather than
-- looking the business up and returning it. A helper that returns an id is an
-- enumeration oracle: any signed-in user could hand it a guessed post UUID and get
-- back the id of the business that owns it. Answering yes/no to a business the
-- caller already named leaks nothing.
create or replace function app.post_belongs_to(target_post_id uuid, target_business_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  -- Scoped to the caller's own memberships. Answering about a business you have
  -- nothing to do with would still confirm a relationship between two ids you
  -- should not be able to correlate.
  select app.is_member_of(target_business_id) and exists (
    select 1 from public.posts p
    where p.id = target_post_id and p.business_id = target_business_id
  );
$$;

-- Answers "does this social account sit in this business?"
--
-- Without this check a member of Business B could schedule their own post onto
-- Business A's connected Instagram account.
create or replace function app.account_belongs_to(target_account_id uuid, target_business_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select app.is_member_of(target_business_id) and exists (
    select 1 from public.social_accounts a
    where a.id = target_account_id and a.business_id = target_business_id
  );
$$;

-- Used only by the audit trigger, which needs the real business id to file the row.
-- Deliberately granted to NOBODY: the trigger runs as the function owner and can
-- call it, while no signed-in user can use it as an enumeration oracle.
create or replace function app.business_of_post_for_audit(target_post_id uuid)
returns uuid
language sql
stable
security definer
set search_path = ''
as $$
  select p.business_id from public.posts p where p.id = target_post_id;
$$;

revoke all on function app.business_of_post_for_audit(uuid) from public;

revoke all on function app.is_member_of(uuid) from public;
revoke all on function app.has_role_in(uuid, public.member_role[]) from public;
revoke all on function app.post_belongs_to(uuid, uuid) from public;
revoke all on function app.account_belongs_to(uuid, uuid) from public;
grant execute on function app.is_member_of(uuid) to authenticated;
grant execute on function app.has_role_in(uuid, public.member_role[]) to authenticated;
grant execute on function app.post_belongs_to(uuid, uuid) to authenticated;
grant execute on function app.account_belongs_to(uuid, uuid) to authenticated;
