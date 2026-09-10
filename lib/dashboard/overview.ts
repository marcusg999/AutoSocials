/**
 * What the dashboard says about a business, worked out from rows rather than in
 * the page, so it can be tested without a database or a browser.
 *
 * The bias here is towards things that are WRONG. A scheduled post that is going
 * out fine needs no attention; one that failed, or is due against an account that
 * is no longer connected, is something only the operator can fix — and this is a
 * tool with no notifications, so the dashboard is the only place it can surface.
 */

export type ScheduledRow = {
  id: string
  scheduled_for: string | null
  status: string
  attempts: number
  last_error: string | null
}

export type AccountRow = {
  id: string
  label: string | null
  status: string
}

export type Overview = {
  scheduled: number
  published: number
  failed: number
  drafts: number
  /** Scheduled, still to come, soonest first. */
  upcoming: ScheduledRow[]
  /** Scheduled, but the time has passed and the worker has not taken it. */
  overdue: ScheduledRow[]
  /** Gave up after its attempts ran out. */
  failures: ScheduledRow[]
  /** Accounts that would fail if something were scheduled to them right now. */
  disconnected: AccountRow[]
}

/** A post is late when its time has passed and it is still sitting there. */
const isPast = (row: ScheduledRow, now: Date) =>
  row.scheduled_for !== null && new Date(row.scheduled_for).getTime() <= now.getTime()

export function summarise(
  scheduledRows: ScheduledRow[],
  accounts: AccountRow[],
  draftCount: number,
  now: Date = new Date(),
): Overview {
  const scheduled = scheduledRows.filter((row) => row.status === 'scheduled')

  const bySoonest = (a: ScheduledRow, b: ScheduledRow) =>
    (a.scheduled_for ?? '').localeCompare(b.scheduled_for ?? '')

  return {
    scheduled: scheduled.length,
    published: scheduledRows.filter((row) => row.status === 'published').length,
    failed: scheduledRows.filter((row) => row.status === 'failed').length,
    drafts: draftCount,
    upcoming: scheduled.filter((row) => !isPast(row, now)).sort(bySoonest),
    // A worker that is not running looks exactly like this, which is the point:
    // "nothing is publishing" should be visible without reading a log.
    overdue: scheduled.filter((row) => isPast(row, now)).sort(bySoonest),
    failures: scheduledRows.filter((row) => row.status === 'failed').sort(bySoonest),
    disconnected: accounts.filter((account) => account.status !== 'connected'),
  }
}
