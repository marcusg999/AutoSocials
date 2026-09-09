-- 0015_editing.down.sql
drop trigger if exists refuse_edit_after_publish on public.posts;
drop function if exists app.refuse_edit_after_publish();
drop function if exists app.post_has_been_published(uuid);
drop index if exists public.posts_business_status_idx;
