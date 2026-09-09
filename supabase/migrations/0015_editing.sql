-- 0015_editing.sql
-- Phase 4: drafts and rescheduling make posts editable from the browser for the
-- first time, and that opens one hole the grants cannot close.
--
-- `authenticated` holds `update (status, body) on posts`, which is right: a draft
-- is meant to be rewritten. But a post that has already been published is not a
-- draft any more. Editing its body would leave the row saying one thing while the
-- thing on Facebook says another, and deleting it would cascade away the
-- scheduled_posts row holding published_at and provider_post_ref -- the only local
-- record that it ever went out.
--
-- A column grant cannot express "editable until published", because the fact that
-- decides it lives on a different table. So it is a trigger.

-- True when any of this post's scheduled rows has actually been published.
create or replace function app.post_has_been_published(p_post_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
      from public.scheduled_posts s
     where s.post_id = p_post_id
       and s.status  = 'published'
  );
$$;

comment on function app.post_has_been_published(uuid) is
  'True when at least one of this post''s scheduled rows went out.';

-- Refuses the edit rather than silently keeping both versions.
create or replace function app.refuse_edit_after_publish()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if tg_op = 'DELETE' then
    if app.post_has_been_published(old.id) then
      raise exception
        'this post has already been published: deleting it would only lose the record';
    end if;
    return old;
  end if;

  -- An UPDATE that changes nothing a reader would notice is allowed through, so
  -- re-saving an unchanged form is not an error.
  if new.body is distinct from old.body or new.status is distinct from old.status then
    if app.post_has_been_published(old.id) then
      raise exception
        'this post has already been published: editing it would only change the local copy';
    end if;
  end if;

  return new;
end;
$$;

comment on function app.refuse_edit_after_publish() is
  'BEFORE trigger on posts: a published post is a record, not a draft.';

drop trigger if exists refuse_edit_after_publish on public.posts;

create trigger refuse_edit_after_publish
  before update or delete on public.posts
  for each row execute function app.refuse_edit_after_publish();

-- The drafts page and the dashboard both read "this business's posts, by status".
create index if not exists posts_business_status_idx
  on public.posts (business_id, status, created_at desc);

-- Same treatment as every other function in schema app: reachable by nobody
-- directly. A trigger function needs no EXECUTE grant to fire.
revoke all on function app.post_has_been_published(uuid)  from public, anon, authenticated;
revoke all on function app.refuse_edit_after_publish()    from public, anon, authenticated;
