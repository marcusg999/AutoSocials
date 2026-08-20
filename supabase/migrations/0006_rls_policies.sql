-- 0006_rls_policies.sql
-- Every policy below is preceded by one plain-English sentence describing it.
--
-- Two kinds of policy are used:
--   PERMISSIVE (the default) grants access -- a row is visible if ANY of them passes.
--   RESTRICTIVE narrows access -- EVERY one of them must pass, no matter what.
-- Tenant membership is permissive. The MFA requirement is restrictive, so it can
-- never be widened by adding another policy later.

-- Table privileges first. RLS filters rows, but Postgres still needs the plain
-- GRANT before a role may touch the table at all. `anon` is granted nothing:
-- a signed-out visitor cannot read a single row from any table here.
grant select, insert, update, delete on public.businesses        to authenticated;
grant select, insert, update, delete on public.business_members  to authenticated;
grant select, insert, update, delete on public.social_accounts   to authenticated;
grant select, insert, update, delete on public.posts             to authenticated;
grant select, insert, update, delete on public.scheduled_posts   to authenticated;
grant select                          on public.audit_log        to authenticated;
grant usage on all sequences in schema public to authenticated;


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
-- ===========================================================================

-- You can see the membership list of a business only if you are a member of it.
drop policy if exists members_select_own_business on public.business_members;
create policy members_select_own_business on public.business_members for select to authenticated
  using (app.is_member_of(business_id));

-- Only an owner of a business may add someone to it.
drop policy if exists members_insert_by_owner on public.business_members;
create policy members_insert_by_owner on public.business_members for insert to authenticated
  with check (app.has_role_in(business_id, array['owner']::public.member_role[]));

-- Only an owner of a business may change someone's role, and only within that same business.
drop policy if exists members_update_by_owner on public.business_members;
create policy members_update_by_owner on public.business_members for update to authenticated
  using      (app.has_role_in(business_id, array['owner']::public.member_role[]))
  with check (app.has_role_in(business_id, array['owner']::public.member_role[]));

-- Only an owner of a business may remove someone from it.
drop policy if exists members_delete_by_owner on public.business_members;
create policy members_delete_by_owner on public.business_members for delete to authenticated
  using (app.has_role_in(business_id, array['owner']::public.member_role[]));


-- ===========================================================================
-- social_accounts
-- ===========================================================================

-- You can see a connected social account only if you are a member of the business that owns it.
drop policy if exists accounts_select_own_business on public.social_accounts;
create policy accounts_select_own_business on public.social_accounts for select to authenticated
  using (app.is_member_of(business_id));

-- You may connect a social account only to a business you are a member of.
drop policy if exists accounts_insert_own_business on public.social_accounts;
create policy accounts_insert_own_business on public.social_accounts for insert to authenticated
  with check (app.is_member_of(business_id));

-- You may edit a social account only if you are a member of its business, and you may not move it to another business.
drop policy if exists accounts_update_own_business on public.social_accounts;
create policy accounts_update_own_business on public.social_accounts for update to authenticated
  using      (app.is_member_of(business_id))
  with check (app.is_member_of(business_id));

-- You may disconnect a social account only if you are a member of its business.
drop policy if exists accounts_delete_own_business on public.social_accounts;
create policy accounts_delete_own_business on public.social_accounts for delete to authenticated
  using (app.is_member_of(business_id));


-- ===========================================================================
-- posts
-- ===========================================================================

-- You can see a post only if you are a member of the business it belongs to.
drop policy if exists posts_select_own_business on public.posts;
create policy posts_select_own_business on public.posts for select to authenticated
  using (app.is_member_of(business_id));

-- You may create a post only inside a business you are a member of.
drop policy if exists posts_insert_own_business on public.posts;
create policy posts_insert_own_business on public.posts for insert to authenticated
  with check (app.is_member_of(business_id));

-- You may edit a post only if you are a member of its business, and you may not move it to another business.
drop policy if exists posts_update_own_business on public.posts;
create policy posts_update_own_business on public.posts for update to authenticated
  using      (app.is_member_of(business_id))
  with check (app.is_member_of(business_id));

-- You may delete a post only if you are a member of its business.
drop policy if exists posts_delete_own_business on public.posts;
create policy posts_delete_own_business on public.posts for delete to authenticated
  using (app.is_member_of(business_id));


-- ===========================================================================
-- scheduled_posts
--
-- This table has no business_id of its own, so it inherits its tenant from the
-- post it schedules. Every write also checks the target social account, because
-- otherwise you could aim your own post at someone else's connected account.
-- ===========================================================================

-- You can see a scheduled post only if you are a member of the business that owns its post.
drop policy if exists scheduled_select_own_business on public.scheduled_posts;
create policy scheduled_select_own_business on public.scheduled_posts for select to authenticated
  using (app.is_member_of(app.business_of_post(post_id)));

-- You may schedule a post only when both the post and the target social account belong to the same business you are a member of.
drop policy if exists scheduled_insert_own_business on public.scheduled_posts;
create policy scheduled_insert_own_business on public.scheduled_posts for insert to authenticated
  with check (
    app.is_member_of(app.business_of_post(post_id))
    and app.business_of_post(post_id) = app.business_of_social_account(social_account_id)
  );

-- You may change a scheduled post only within your own business, and it must still point at that business's post and account afterwards.
drop policy if exists scheduled_update_own_business on public.scheduled_posts;
create policy scheduled_update_own_business on public.scheduled_posts for update to authenticated
  using (app.is_member_of(app.business_of_post(post_id)))
  with check (
    app.is_member_of(app.business_of_post(post_id))
    and app.business_of_post(post_id) = app.business_of_social_account(social_account_id)
  );

-- You may unschedule a post only if you are a member of the business that owns it.
drop policy if exists scheduled_delete_own_business on public.scheduled_posts;
create policy scheduled_delete_own_business on public.scheduled_posts for delete to authenticated
  using (app.is_member_of(app.business_of_post(post_id)));


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
