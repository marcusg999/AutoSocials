-- Reverses 0007_audit_triggers.sql
do $$
declare audited_table text;
begin
  foreach audited_table in array array[
    'businesses', 'business_members', 'social_accounts', 'posts', 'scheduled_posts'
  ] loop
    execute format('drop trigger if exists audit_changes on public.%I', audited_table);
  end loop;
end $$;
drop function if exists app.audit_row_change();
