import { csrfField } from '@/lib/security/csrf'
import { requireMfaSession } from '@/lib/security/session'
import { listBusinesses, resolveActiveBusiness } from '@/lib/business'
import { parsePostContent } from '@/lib/connectors/content'
import {
  dayKeyUtc, formatDayUtc, formatUtc, relativeToNow, toScheduleValue,
} from '@/lib/publishing/schedule-time'

import { cancelScheduledPostAction, reschedulePostAction } from '../composer/actions'

export const dynamic = 'force-dynamic'

/** What the operator needs to see, in the order they need to see it. */
const STATUS_LABEL: Record<string, string> = {
  scheduled: 'Scheduled',
  published: 'Published',
  failed: 'Failed',
}

export default async function CalendarPage({
  searchParams,
}: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  // Layer 2. The page establishes its own session rather than trusting the proxy.
  const { supabase } = await requireMfaSession()
  const params = await searchParams
  const csrf = await csrfField()

  const businesses = await listBusinesses(supabase)
  const active = await resolveActiveBusiness(businesses)

  // Row level security scopes every table in this join, including the two it
  // reaches through. The page does no tenancy filtering of its own.
  const { data: rows } = await supabase
    .from('scheduled_posts')
    .select(`
      id, business_id, scheduled_for, status, attempts, last_error,
      provider_post_ref, published_at,
      posts ( body ),
      social_accounts ( label, platform )
    `)
    .order('scheduled_for', { ascending: false })

  const forBusiness = (rows ?? []).filter((row) => row.business_id === active?.id)

  // Grouped by UTC day, because a flat list of timestamps is unreadable past about
  // a dozen rows and the whole point of a calendar is "what is going out that day".
  const days = new Map<string, typeof forBusiness>()
  for (const row of forBusiness) {
    const key = dayKeyUtc(row.scheduled_for)
    days.set(key, [...(days.get(key) ?? []), row])
  }

  return (
    <main>
      <h1>Calendar</h1>
      <p className="lede">
        Everything scheduled for <strong>{active?.name ?? 'no business'}</strong>. All times UTC.
      </p>

      {params.scheduled ? <div className="panel">Scheduled.</div> : null}
      {params.moved ? <div className="panel">Moved.</div> : null}

      {forBusiness.length === 0 ? (
        <div className="panel">
          <p className="muted">
            Nothing scheduled. Write something in the <a href="/dashboard/composer">Composer</a>.
          </p>
        </div>
      ) : (
        [...days.entries()].map(([dayKey, dayRows]) => (
          <div className="panel" key={dayKey}>
            <h2>{formatDayUtc(dayKey)}</h2>
            <ul className="rows">
              {dayRows.map((row) => {
                // posts/social_accounts come back as an object or an array depending
                // on how the join is inferred; normalise rather than trusting one.
                const post = Array.isArray(row.posts) ? row.posts[0] : row.posts
                const account = Array.isArray(row.social_accounts)
                  ? row.social_accounts[0]
                  : row.social_accounts
                const content = parsePostContent(post?.body)
                const preview = content.text.trim() === ''
                  ? '(image only)'
                  : content.text.slice(0, 80) + (content.text.length > 80 ? '…' : '')

                return (
                  <li key={row.id}>
                    <span>
                      <strong>{formatUtc(row.scheduled_for)}</strong>
                      <span className="badge">{STATUS_LABEL[row.status] ?? row.status}</span>
                      {row.status === 'scheduled'
                        ? <span className="muted"> {relativeToNow(row.scheduled_for)}</span>
                        : null}
                      <br />
                      {preview}
                      <br />
                      <span className="muted">
                        {account?.label ?? 'unknown account'} — {account?.platform ?? '?'}
                        {row.published_at ? ` · published ${formatUtc(row.published_at)}` : null}
                        {row.provider_post_ref ? ` · ${row.provider_post_ref}` : null}
                        {row.attempts > 0 && row.status !== 'published'
                          ? ` · ${row.attempts} attempt(s)` : null}
                      </span>
                      {/* A failure the operator cannot see is a post they think went
                          out, so the provider's reason is shown rather than logged. */}
                      {row.last_error && row.status !== 'published' ? (
                        <>
                          <br />
                          <span className="muted">Last error: {row.last_error}</span>
                        </>
                      ) : null}
                    </span>

                    {row.status === 'scheduled' ? (
                      <span className="actions">
                        {/* Moving a post is an UPDATE of scheduled_for, which is the
                            only column 0014 leaves a human on this table. */}
                        <form action={reschedulePostAction} className="inline">
                          {csrf}
                          <input type="hidden" name="scheduledId" value={row.id} />
                          <input type="datetime-local" name="scheduledFor" required
                            defaultValue={toScheduleValue(row.scheduled_for)} />
                          <button type="submit" className="secondary">Move</button>
                        </form>
                        <form action={cancelScheduledPostAction} className="inline">
                          {csrf}
                          <input type="hidden" name="scheduledId" value={row.id} />
                          <button type="submit">Cancel</button>
                        </form>
                      </span>
                    ) : row.status === 'published' ? null : (
                      <form action={cancelScheduledPostAction} className="inline">
                        {csrf}
                        <input type="hidden" name="scheduledId" value={row.id} />
                        <button type="submit">Cancel</button>
                      </form>
                    )}
                  </li>
                )
              })}
            </ul>
          </div>
        ))
      )}
    </main>
  )
}
