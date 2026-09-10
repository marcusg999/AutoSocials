-- 0009_seed_businesses.sql
-- Creates the seven placeholder businesses. Safe to run repeatedly: it matches on
-- name, so a second run changes nothing. Rename them freely afterwards -- this
-- migration will not recreate or overwrite a renamed business.

insert into public.businesses (name, timezone)
select v.name, 'UTC'
from (values
  ('BUSINESS_1'), ('BUSINESS_2'), ('BUSINESS_3'), ('BUSINESS_4'),
  ('BUSINESS_5'), ('BUSINESS_6'), ('BUSINESS_7')
) as v(name)
where not exists (
  select 1 from public.businesses b where b.name = v.name
);

-- Makes one user an owner of every business that exists. Run by the seed script
-- after the admin account has been created in Supabase Auth.
create or replace function app.grant_admin_all_businesses(admin_email text)
returns int
language plpgsql
security definer
set search_path = ''
as $$
declare
  admin_id      uuid;
  rows_added    int;
begin
  select id into admin_id from auth.users where email = lower(admin_email);
  if admin_id is null then
    raise exception 'no auth user with email %', admin_email;
  end if;

  insert into public.business_members (business_id, user_id, role)
  select b.id, admin_id, 'owner'
  from public.businesses b
  on conflict (business_id, user_id) do nothing;

  get diagnostics rows_added = row_count;
  return rows_added;
end;
$$;

revoke all on function app.grant_admin_all_businesses(text) from public;
grant execute on function app.grant_admin_all_businesses(text) to service_role;
