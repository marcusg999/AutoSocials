-- 0016_assistant.down.sql
drop trigger if exists audit_changes on public.post_suggestions;
revoke all on public.post_suggestions from authenticated;
drop table if exists public.post_suggestions;
