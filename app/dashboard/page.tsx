import { csrfField } from '@/lib/security/csrf'
import { requireMfaSession } from '@/lib/security/session'
import { listBusinesses, resolveActiveBusiness } from '@/lib/business'
import { summarise } from '@/lib/dashboard/overview'
import { formatUtc, relativeToNow } from '@/lib/publishing/schedule-time'

import { switchBusinessAction } from './actions'

export const dynamic = 'force-dynamic'

export default async function DashboardPage() {
  // Layer 2, repeated here rather than inherited from the layout.
  const { supabase } = await requireMfaSession()

  const businesses = await listBusinesses(supabase)
  const active = await resolveActiveBusiness(businesses)

  // Three reads, all filtered by the database. The page picks which of the
  // caller's own businesses is on screen and does no other filtering.
  const [{ data: scheduledRows }, { data: accountRows }, { data: draftRows }] = await Promise.all([
    supabase
      .from('scheduled_posts')
      .select('id, business_id, scheduled_for, status, attempts, last_error')
      .order('scheduled_for', { ascending: true }),
    supabase.from('social_accounts').select('id, business_id, label, status'),
    supabase.from('posts').select('id, business_id').eq('status', 'draft'),
  ])

  const mine = <T extends { business_id: string }>(rows: T[] | null) =>
    (rows ?? []).filter((row) => row.business_id === active?.id)

  const overview = summarise(
    mine(scheduledRows), mine(accountRows), mine(draftRows).length)

  return (
    <main>
      <h1>{active?.name ?? 'PostDeck'}</h1>
      <p className="lede">
        What is happening for this business. All times UTC.
      </p>

      {businesses.length === 0 ? (
        <div className="panel">
          <p className="muted">
            You are not a member of any business yet. An owner needs to add you before anything
            appears here.
          </p>
        </div>
      ) : (
        <>
          <div className="panel counts">
            <span><strong>{overview.scheduled}</strong> scheduled</span>
            <span><strong>{overview.published}</strong> published</span>
            <span><strong>{overview.failed}</strong> failed</span>
            <span><strong>{overview.drafts}</strong> drafts</span>
          </div>

          {/* Problems first. This app sends no notifications, so anything wrong is
              only ever seen because it is on this page. */}
          {overview.disconnected.length > 0 ? (
            <div className="panel">
              <h2>Accounts needing attention</h2>
              <ul className="rows">
                {overview.disconnected.map((account) => (
                  <li key={account.id}>
                    <span>{account.label ?? 'unnamed account'}</span>
                    <span className="badge">{account.status}</span>
                  </li>
                ))}
              </ul>
              <p className="muted">
                Anything scheduled to these will fail. Reconnect on the{' '}
                <a href="/dashboard/accounts">Accounts</a> page.
              </p>
            </div>
          ) : null}

          {overview.overdue.length > 0 ? (
            <div className="panel">
              <h2>Overdue</h2>
              <p className="muted">
                Past their time and still waiting. If this list is not emptying, the worker
                (<code>npm run publish:due</code>) is not running.
              </p>
              <ul className="rows">
                {overview.overdue.slice(0, 10).map((row) => (
                  <li key={row.id}>
                    <span>{formatUtc(row.scheduled_for)}</span>
                    <span className="muted">{relativeToNow(row.scheduled_for)}</span>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}

          {overview.failures.length > 0 ? (
            <div className="panel">
              <h2>Failed</h2>
              <ul className="rows">
                {overview.failures.slice(0, 10).map((row) => (
                  <li key={row.id}>
                    <span>
                      {formatUtc(row.scheduled_for)}
                      <br />
                      <span className="muted">
                        {row.attempts} attempt(s) — {row.last_error ?? 'no reason recorded'}
                      </span>
                    </span>
                  </li>
                ))}
              </ul>
              <p className="muted">
                A failed post stops after five attempts and stays there.{' '}
                <a href="/dashboard/calendar">Calendar</a> has the full list.
              </p>
            </div>
          ) : null}

          <div className="panel">
            <h2>Next up</h2>
            {overview.upcoming.length === 0 ? (
              <p className="muted">
                Nothing scheduled. Write something in the{' '}
                <a href="/dashboard/composer">Composer</a>.
              </p>
            ) : (
              <ul className="rows">
                {overview.upcoming.slice(0, 5).map((row) => (
                  <li key={row.id}>
                    <span>{formatUtc(row.scheduled_for)}</span>
                    <span className="muted">{relativeToNow(row.scheduled_for)}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <form action={switchBusinessAction} className="panel switcher">
            {await csrfField()}
            <div className="field">
              <label htmlFor="businessId">Active business</label>
              <select id="businessId" name="businessId" defaultValue={active?.id ?? ''}>
                {businesses.map((business) => (
                  <option key={business.id} value={business.id}>
                    {business.name}
                  </option>
                ))}
              </select>
            </div>
            <button type="submit">Switch</button>
          </form>
        </>
      )}
    </main>
  )
}
