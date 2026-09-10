-- 0016_assistant.sql
-- Phase 5: where the assistant's suggestions live.
--
-- Two reasons this is a table rather than a value returned from a server action.
--
-- The first is a rule this project has held since Phase 1: an action returns
-- Promise<void> and reports by redirecting, because a return value travels in the
-- flight payload -- a channel the secret scanner structurally cannot read. A
-- suggestion is generated text, so handing it back that way would put the one
-- thing the assistant produces into the one channel nothing checks.
--
-- The second is that a suggestion is worth keeping. It was generated from the
-- operator's own draft, it cost money to produce, and the audit trail should be
-- able to say what was proposed and whether a human took it.
--
-- What is NOT stored: anything the model was told beyond the draft itself. The
-- system prompt is in the source tree where it can be read and reviewed, not
-- copied into every row.

create table if not exists public.post_suggestions (
  id          uuid primary key default gen_random_uuid(),
  business_id uuid not null references public.businesses (id) on delete cascade,
  -- Which draft it was generated for, when there was one. Null means it was
  -- generated from whatever was typed into the composer and never saved.
  post_id     uuid references public.posts (id) on delete cascade,
  created_by  uuid references auth.users (id) on delete set null,
  -- The suggested post text. Never the credential, never the system prompt.
  suggestion  text not null,
  -- Which model wrote it, so a change of model is visible in the record rather
  -- than being an invisible change in behaviour.
  model       text not null,
  created_at  timestamptz not null default now()
);

create index if not exists post_suggestions_business_idx
  on public.post_suggestions (business_id, created_at desc);

alter table public.post_suggestions enable row level security;
alter table public.post_suggestions force  row level security;

-- A signed-in user who has not passed a TOTP challenge sees and writes nothing, anywhere.
drop policy if exists mfa_required on public.post_suggestions;
create policy mfa_required on public.post_suggestions as restrictive for all to authenticated
  using (app.has_completed_mfa()) with check (app.has_completed_mfa());

-- You can see a suggestion only if you are a member of the business it was made for.
drop policy if exists post_suggestions_select_own_business on public.post_suggestions;
create policy post_suggestions_select_own_business on public.post_suggestions
  for select to authenticated
  using (app.is_member_of(business_id));

-- Only an owner or manager may ask for a suggestion, only in their own business,
-- and only under their own name -- the same rule as writing a post, because a
-- suggestion is a draft of one.
drop policy if exists post_suggestions_insert_own_business on public.post_suggestions;
create policy post_suggestions_insert_own_business on public.post_suggestions
  for insert to authenticated
  with check (
    app.has_role_in(business_id, array['owner','manager']::public.member_role[])
    and created_by = auth.uid()
  );

-- Only an owner or manager may throw a suggestion away.
drop policy if exists post_suggestions_delete_own_business on public.post_suggestions;
create policy post_suggestions_delete_own_business on public.post_suggestions
  for delete to authenticated
  using (app.has_role_in(business_id, array['owner','manager']::public.member_role[]));

-- No UPDATE policy and no UPDATE grant, deliberately. A suggestion is a record of
-- what the model actually said. Editing one in place would make it impossible to
-- tell the model's words from the operator's, which is the whole question this
-- table exists to answer. Rewriting happens in the composer, on the post.
grant select, insert, delete on public.post_suggestions to authenticated;

-- Row changes are audited by the same trigger as every other business-scoped
-- table. 0007 attached it by name to the five tables that existed then; this is
-- the sixth, and it is attached here rather than by editing that migration.
drop trigger if exists audit_changes on public.post_suggestions;
create trigger audit_changes
  after insert or update or delete on public.post_suggestions
  for each row execute function app.audit_row_change();
