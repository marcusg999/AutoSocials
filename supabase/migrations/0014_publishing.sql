-- 0014_publishing.sql
-- Phase 3: what a scheduled post needs in order to actually be published, and the
-- two functions a worker uses to do it safely.
--
-- The hard problem here is not "call the API". It is that a worker can crash, be
-- restarted, or be run twice, and a post published twice is not recoverable -- you
-- cannot un-post something a follower already saw. So the claim is a database
-- operation with a lease, not an application-level flag.

alter table public.scheduled_posts
  -- The lease. NULL means unclaimed; a time in the past means the claim expired
  -- because the worker holding it died, and the row is free again.
  add column if not exists locked_until      timestamptz,
  -- Which worker holds it. Diagnostic only -- correctness comes from locked_until.
  add column if not exists locked_by         text,
  add column if not exists published_at      timestamptz,
  -- What the platform called the thing it created, so a human can go and find it.
  add column if not exists provider_post_ref text,
  -- Why the last attempt failed. Shown on the calendar, because a failure the
  -- operator cannot see is a post they think went out.
  add column if not exists last_error        text,
  -- Backoff. A row is due when BOTH scheduled_for and next_attempt_at have passed.
  add column if not exists next_attempt_at   timestamptz not null default now();

-- The worker only ever looks for rows that are due, unclaimed and still scheduled.
-- Without this it scans the table on every poll.
create index if not exists scheduled_posts_claimable_idx
  on public.scheduled_posts (scheduled_for, next_attempt_at)
  where status = 'scheduled';

-- ===========================================================================
-- Narrow the UPDATE grant.
--
-- Until this migration `authenticated` held a table-wide UPDATE on
-- scheduled_posts, which was harmless while every column on it was the user's own
-- business. It stops being harmless the moment the columns above exist: an owner
-- could set published_at and provider_post_ref by hand and produce a row that says
-- a post went out when it never did -- forging the record in the one place the
-- operator looks to find out what happened.
--
-- So the grant is narrowed to the single column a human legitimately changes: when
-- it should go out. Everything else about a scheduled post's lifecycle belongs to
-- the worker, which runs as service_role and is unaffected by this grant. This is
-- the same treatment posts.created_by and social_accounts.encrypted_credential_ref
-- already get, for the same reason.
--
-- Cancelling is a DELETE, which is still granted. Rescheduling is an UPDATE of
-- scheduled_for, which is still granted. Nothing a human should do is lost.
-- ===========================================================================
revoke update on public.scheduled_posts from authenticated;
grant update (scheduled_for) on public.scheduled_posts to authenticated;

-- ===========================================================================
-- Claiming
-- ===========================================================================

/**
 * Take up to p_batch due rows, leasing each for p_lease.
 *
 * FOR UPDATE SKIP LOCKED is the whole point: two workers running concurrently take
 * disjoint sets rather than blocking on each other or, far worse, both taking the
 * same row and publishing it twice. The lease then covers the case the lock cannot:
 * a worker that takes a row and dies holds no database lock afterwards, so without
 * locked_until the row would be immediately re-claimable while its API call was
 * possibly still in flight.
 *
 * attempts is incremented HERE, at claim time, not on completion. A worker that
 * crashes mid-publish must still burn an attempt, or a row that reliably kills the
 * worker is retried forever.
 */
create or replace function app.claim_due_scheduled_posts(
  p_worker text,
  p_batch  int      default 10,
  p_lease  interval default interval '5 minutes'
)
returns table (
  scheduled_id         uuid,
  business_id          uuid,
  post_id              uuid,
  social_account_id    uuid,
  platform             public.social_platform,
  provider_account_ref text,
  body                 jsonb,
  attempts             int
)
language plpgsql
security definer
set search_path = ''
as $$
begin
  return query
  with due as (
    select s.id, s.post_id, s.social_account_id
      from public.scheduled_posts s
      join public.social_accounts a on a.id = s.social_account_id
     where s.status = 'scheduled'
       and s.scheduled_for   <= now()
       and s.next_attempt_at <= now()
       and (s.locked_until is null or s.locked_until < now())
       -- A disconnected account has no credential to publish with. Leaving the row
       -- 'scheduled' is deliberate: reconnect the account and it goes out.
       and a.status = 'connected'
     order by s.scheduled_for
     -- Bounded regardless of what the caller asks for. A worker that asks for a
     -- million rows leases a million rows, and every one of them is unavailable to
     -- every other worker until the lease expires.
     limit greatest(1, least(coalesce(p_batch, 10), 100))
     for update of s skip locked
  )
  update public.scheduled_posts s
     set locked_until = now() + p_lease,
         locked_by    = p_worker,
         attempts     = s.attempts + 1
    from due
    join public.posts p           on p.id = due.post_id
    join public.social_accounts a on a.id = due.social_account_id
   where s.id = due.id
  returning s.id, s.business_id, s.post_id, s.social_account_id,
            a.platform, a.provider_account_ref, p.body, s.attempts;
end;
$$;

/**
 * Record the outcome of one attempt.
 *
 * Success is terminal. Failure is terminal only once attempts run out; before that
 * the row is released with a backoff so a transient provider error resolves itself
 * without anyone watching.
 *
 * Note what is NOT here: an audit write. scheduled_posts already carries the
 * audit_changes trigger from 0007, so the row change and its audit entry happen in
 * one transaction and cannot disagree. Writing one here as well would double-log
 * every attempt and invite the two records to drift.
 */
create or replace function app.complete_scheduled_post(
  p_scheduled_id      uuid,
  p_ok                boolean,
  p_provider_post_ref text default null,
  p_error             text default null,
  p_max_attempts      int  default 5
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  tried int;
begin
  select attempts into tried
    from public.scheduled_posts where id = p_scheduled_id;
  if tried is null then
    raise exception 'no such scheduled post: %', p_scheduled_id
      using errcode = 'no_data_found';
  end if;

  if p_ok then
    update public.scheduled_posts
       set status            = 'published',
           published_at      = now(),
           provider_post_ref = p_provider_post_ref,
           last_error        = null,
           locked_until      = null,
           locked_by         = null
     where id = p_scheduled_id;
    return;
  end if;

  update public.scheduled_posts
     set status = case when tried >= greatest(1, p_max_attempts)
                       then 'failed'::public.post_status
                       else 'scheduled'::public.post_status end,
         -- Truncated: this is provider text and it is shown to the operator. The
         -- connectors already strip the token out of Meta's error bodies, and this
         -- is the second fence rather than the first.
         last_error = left(coalesce(p_error, 'unknown error'), 500),
         -- Exponential, from one minute: 1, 3, 9, 27... A failed row that is out of
         -- attempts keeps its next_attempt_at, which is meaningless once the status
         -- is 'failed' and harmless.
         next_attempt_at = now() + (interval '1 minute' * power(3, greatest(0, tried - 1))),
         locked_until = null,
         locked_by    = null
   where id = p_scheduled_id;
end;
$$;

-- Both are service_role only. A browser session must never be able to claim a row
-- (it would take work away from the worker) or declare one published (it would
-- forge the record).
revoke all on function app.claim_due_scheduled_posts(text, int, interval)
  from public, anon, authenticated;
grant execute on function app.claim_due_scheduled_posts(text, int, interval)
  to service_role;

revoke all on function app.complete_scheduled_post(uuid, boolean, text, text, int)
  from public, anon, authenticated;
grant execute on function app.complete_scheduled_post(uuid, boolean, text, text, int)
  to service_role;
