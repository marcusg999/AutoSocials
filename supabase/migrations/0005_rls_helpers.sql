-- 0005_rls_helpers.sql
-- The three questions every RLS policy in this app asks. They live here, after the
-- tables exist, because Postgres validates a SQL function body when you create it.

-- Returns true when the signed-in user belongs to the given business.
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
  select exists (
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
  select exists (
    select 1 from public.business_members m
    where m.business_id = target_business_id
      and m.user_id = (select auth.uid())
      and m.role = any(allowed)
  );
$$;

-- Returns the business a post belongs to, ignoring RLS.
-- scheduled_posts has no business_id of its own, so it has to ask its parent post.
create or replace function app.business_of_post(target_post_id uuid)
returns uuid
language sql
stable
security definer
set search_path = ''
as $$
  select p.business_id from public.posts p where p.id = target_post_id;
$$;

-- Returns the business a social account belongs to, ignoring RLS.
create or replace function app.business_of_social_account(target_account_id uuid)
returns uuid
language sql
stable
security definer
set search_path = ''
as $$
  select a.business_id from public.social_accounts a where a.id = target_account_id;
$$;

revoke all on function app.is_member_of(uuid) from public;
revoke all on function app.has_role_in(uuid, public.member_role[]) from public;
revoke all on function app.business_of_post(uuid) from public;
revoke all on function app.business_of_social_account(uuid) from public;
grant execute on function app.is_member_of(uuid) to authenticated;
grant execute on function app.has_role_in(uuid, public.member_role[]) to authenticated;
grant execute on function app.business_of_post(uuid) to authenticated;
grant execute on function app.business_of_social_account(uuid) to authenticated;
