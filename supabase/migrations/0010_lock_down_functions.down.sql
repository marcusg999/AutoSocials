alter default privileges grant execute on functions to public;
-- Reverses 0010_lock_down_functions.sql by restoring the grants the earlier
-- migrations made. It does NOT restore PUBLIC execute: that was never wanted.
grant execute on function app.has_completed_mfa()                     to authenticated;
grant execute on function app.is_member_of(uuid)                      to authenticated;
grant execute on function app.has_role_in(uuid, public.member_role[]) to authenticated;
grant execute on function app.post_belongs_to(uuid, uuid)             to authenticated;
grant execute on function app.account_belongs_to(uuid, uuid)          to authenticated;
