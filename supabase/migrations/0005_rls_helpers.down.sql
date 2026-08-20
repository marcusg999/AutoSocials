-- Reverses 0005_rls_helpers.sql
drop function if exists app.post_and_account_share_business(uuid, uuid);
drop function if exists app.may_use_post(uuid);
drop function if exists app.business_of_post_for_audit(uuid);
drop function if exists app.has_role_in(uuid, public.member_role[]);
drop function if exists app.is_member_of(uuid);
