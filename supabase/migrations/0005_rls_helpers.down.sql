-- Reverses 0005_rls_helpers.sql
drop function if exists app.business_of_social_account(uuid);
drop function if exists app.business_of_post(uuid);
drop function if exists app.has_role_in(uuid, public.member_role[]);
drop function if exists app.is_member_of(uuid);
