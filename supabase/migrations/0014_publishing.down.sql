-- Reverses 0014_publishing.sql.

drop function if exists app.complete_scheduled_post(uuid, boolean, text, text, int);
drop function if exists app.claim_due_scheduled_posts(text, int, interval);

drop index if exists public.scheduled_posts_claimable_idx;

-- Put the table-wide UPDATE grant back, because that is what 0006 left in place and
-- rolling back has to restore the state the previous migration described -- not an
-- improved version of it.
revoke update on public.scheduled_posts from authenticated;
grant update on public.scheduled_posts to authenticated;

alter table public.scheduled_posts
  drop column if exists next_attempt_at,
  drop column if exists last_error,
  drop column if exists provider_post_ref,
  drop column if exists published_at,
  drop column if exists locked_by,
  drop column if exists locked_until;
