-- Reverses 0004_audit_log.sql
drop function if exists app.write_audit(text, uuid, text, text, jsonb, inet, uuid);
drop function if exists app.write_audit(text, uuid, text, text, jsonb, inet);
drop trigger if exists audit_log_no_delete on public.audit_log;
drop trigger if exists audit_log_no_update on public.audit_log;
drop function if exists app.audit_log_is_append_only();
drop table if exists public.audit_log;
