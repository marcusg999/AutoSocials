-- 0007_audit_triggers.sql
-- Makes the audit trail automatic. Every insert, update and delete on a
-- business-scoped table writes an audit_log row, whether it came from the web app,
-- a worker, psql or a future connector. Nothing has to remember to log.

-- Works out which business a row belongs to and appends one audit_log row for it.
-- Deliberately records WHICH columns changed, never their values: post bodies and
-- credential references have no business being copied into a second table.
create or replace function app.audit_row_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  row_snapshot   jsonb;
  target_business uuid;
  changed_columns text[];
begin
  row_snapshot := to_jsonb(coalesce(new, old));

  -- Most tables carry business_id. scheduled_posts has to ask its parent post.
  if row_snapshot ? 'business_id' then
    target_business := (row_snapshot ->> 'business_id')::uuid;
  elsif tg_table_name = 'businesses' then
    target_business := (row_snapshot ->> 'id')::uuid;
  elsif row_snapshot ? 'post_id' then
    target_business := app.business_of_post((row_snapshot ->> 'post_id')::uuid);
  end if;

  if tg_op = 'UPDATE' then
    select coalesce(array_agg(key order by key), '{}')
      into changed_columns
    from jsonb_each(to_jsonb(new))
    where to_jsonb(new) -> key is distinct from to_jsonb(old) -> key;
  end if;

  perform app.write_audit(
    p_action      => tg_table_name || '.' || lower(tg_op),
    p_business_id => target_business,
    p_target_type => tg_table_name,
    p_target_id   => row_snapshot ->> 'id',
    p_metadata    => jsonb_strip_nulls(jsonb_build_object(
                       'operation', lower(tg_op),
                       'changed_columns', changed_columns
                     ))
  );

  return null; -- AFTER trigger: the return value is ignored.
end;
$$;

comment on function app.audit_row_change() is
  'AFTER trigger: appends an audit_log row naming the table, operation and changed columns.';

-- Attach the same trigger to every business-scoped table.
do $$
declare
  audited_table text;
begin
  foreach audited_table in array array[
    'businesses', 'business_members', 'social_accounts', 'posts', 'scheduled_posts'
  ] loop
    execute format('drop trigger if exists audit_changes on public.%I', audited_table);
    execute format(
      'create trigger audit_changes after insert or update or delete on public.%I
         for each row execute function app.audit_row_change()',
      audited_table);
  end loop;
end $$;
