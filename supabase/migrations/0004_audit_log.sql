-- 0004_audit_log.sql
-- Append-only record of every mutating action. An audit trail you can edit is not
-- an audit trail, so this table is write-once: no UPDATE, no DELETE, by anyone.

create table if not exists public.audit_log (
  id             bigint generated always as identity primary key,
  -- Deliberately NOT foreign keys. An audit trail has to outlive the thing it
  -- describes: if deleting a business blanked these columns you would lose exactly
  -- the history you most need. ON DELETE SET NULL would also be an UPDATE, which
  -- the append-only triggers below correctly refuse.
  actor_user_id  uuid,
  business_id    uuid,
  action         text not null check (length(trim(action)) between 1 and 100),
  target_type    text,
  target_id      text,
  metadata       jsonb not null default '{}'::jsonb,
  ip             inet,
  created_at     timestamptz not null default now()
);

create index if not exists audit_log_business_idx on public.audit_log (business_id, created_at desc);
create index if not exists audit_log_actor_idx    on public.audit_log (actor_user_id, created_at desc);

alter table public.audit_log enable row level security;
alter table public.audit_log force row level security;

-- Blocks every attempt to rewrite history, including by the table owner and
-- service_role. Triggers fire regardless of RLS, so this cannot be policy-bypassed.
create or replace function app.audit_log_is_append_only()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  raise exception 'audit_log is append-only: % is not permitted', tg_op
    using errcode = 'insufficient_privilege';
end;
$$;

drop trigger if exists audit_log_no_update on public.audit_log;
create trigger audit_log_no_update
  before update on public.audit_log
  for each row execute function app.audit_log_is_append_only();

drop trigger if exists audit_log_no_delete on public.audit_log;
create trigger audit_log_no_delete
  before delete on public.audit_log
  for each row execute function app.audit_log_is_append_only();

-- The one supported way to write an audit row.
--
-- SECURITY DEFINER so it can insert past RLS, but it stamps the actor from the
-- live JWT rather than trusting a caller-supplied user id.
--
-- This function is granted to service_role ONLY. It performs no membership or MFA
-- check of its own, precisely because trusted server-side callers need to log
-- events (a failed login) where there is no session to check. Signed-in users
-- reach it through public.record_audit_event(), which does check. Granting this
-- directly to `authenticated` would hand every user an RLS-bypassing write into
-- any tenant's permanent, undeletable audit trail.
create or replace function app.write_audit(
  p_action      text,
  p_business_id uuid    default null,
  p_target_type text    default null,
  p_target_id   text    default null,
  p_metadata    jsonb   default '{}'::jsonb,
  p_ip          inet    default null,
  p_actor_user_id uuid  default null
)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  new_id bigint;
  actor  uuid;
begin
  -- The JWT always wins. p_actor_user_id is only consulted when there is no
  -- session at all -- which happens exactly once, when our own server records a
  -- FAILED login on behalf of someone who never got a session. Because the JWT
  -- takes precedence, no session can ever use this parameter to impersonate.
  actor := coalesce((select auth.uid()), p_actor_user_id);

  insert into public.audit_log
    (actor_user_id, business_id, action, target_type, target_id, metadata, ip)
  values
    (actor, p_business_id, p_action, p_target_type, p_target_id,
     coalesce(p_metadata, '{}'::jsonb), p_ip)
  returning id into new_id;
  return new_id;
end;
$$;

comment on function app.write_audit is
  'Appends one audit_log row, stamping the actor from the current JWT.';

revoke all on function app.write_audit(text, uuid, text, text, jsonb, inet, uuid) from public;
grant execute on function app.write_audit(text, uuid, text, text, jsonb, inet, uuid) to service_role;

revoke all on function app.audit_log_is_append_only() from public;
