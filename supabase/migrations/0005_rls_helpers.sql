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

-- Answers "may I use this post?" -- true when the post exists and the signed-in
-- user is a member of its business.
--
-- Note it returns a BOOLEAN, not the business id. An earlier version returned the
-- business_id for any post id handed to it, which let any signed-in user turn a
-- guessed post UUID into the id of the business that owns it. Returning only yes/no
-- tells the caller nothing they were not already entitled to know.
create or replace function app.may_use_post(target_post_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.posts p
    join public.business_members m on m.business_id = p.business_id
    where p.id = target_post_id
      and m.user_id = (select auth.uid())
  );
$$;

-- Answers "do this post and this social account belong to the same business?"
--
-- scheduled_posts joins a post to a connected account. Without this check a member
-- of Business B could schedule their own post onto Business A's Instagram account,
-- because the post half of the row would look perfectly legitimate.
create or replace function app.post_and_account_share_business(
  target_post_id    uuid,
  target_account_id uuid
)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.posts p
    join public.social_accounts a on a.business_id = p.business_id
    where p.id = target_post_id
      and a.id = target_account_id
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
revoke all on function app.may_use_post(uuid) from public;
revoke all on function app.post_and_account_share_business(uuid, uuid) from public;
grant execute on function app.is_member_of(uuid) to authenticated;
grant execute on function app.has_role_in(uuid, public.member_role[]) to authenticated;
grant execute on function app.may_use_post(uuid) to authenticated;
grant execute on function app.post_and_account_share_business(uuid, uuid) to authenticated;
