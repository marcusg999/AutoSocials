/**
 * What the dashboard and calendar work out from rows.
 *
 * These are the two places an operator finds out that something went wrong, and
 * this app sends no notifications — so a summary that quietly drops a failure, or
 * a calendar that files a post under the wrong day, is the difference between
 * noticing and not noticing.
 */
import { describe, expect, test } from 'vitest'

import { summarise, type AccountRow, type ScheduledRow } from '@/lib/dashboard/overview'
import {
  dayKeyUtc, formatDayUtc, relativeToNow, toScheduleValue,
} from '@/lib/publishing/schedule-time'

const NOW = new Date('2026-09-09T12:00:00.000Z')

function row(overrides: Partial<ScheduledRow> = {}): ScheduledRow {
  return {
    id: 'a', scheduled_for: '2026-09-09T15:00:00.000Z', status: 'scheduled',
    attempts: 0, last_error: null, ...overrides,
  }
}

const account = (overrides: Partial<AccountRow> = {}): AccountRow =>
  ({ id: 'acc', label: 'Page', status: 'connected', ...overrides })

describe('the dashboard summary', () => {
  test('counts each status separately', () => {
    const overview = summarise([
      row({ id: '1' }),
      row({ id: '2' }),
      row({ id: '3', status: 'published' }),
      row({ id: '4', status: 'failed' }),
    ], [], 7, NOW)

    expect(overview.scheduled).toBe(2)
    expect(overview.published).toBe(1)
    expect(overview.failed).toBe(1)
    expect(overview.drafts).toBe(7)
  })

  test('splits scheduled posts into still-to-come and overdue', () => {
    const overview = summarise([
      row({ id: 'later', scheduled_for: '2026-09-09T18:00:00.000Z' }),
      row({ id: 'past', scheduled_for: '2026-09-09T09:00:00.000Z' }),
    ], [], 0, NOW)

    expect(overview.upcoming.map((r) => r.id)).toEqual(['later'])
    expect(overview.overdue.map((r) => r.id)).toEqual(['past'])
  })

  /**
   * The reason overdue exists at all. Nothing publishes unless an external
   * scheduler runs the worker, and a worker that silently stopped looks like
   * posts that never go out — with no error anywhere, because nothing tried.
   */
  test('a post whose time has passed is overdue, not upcoming', () => {
    const overview = summarise([row({ scheduled_for: '2026-09-09T11:59:00.000Z' })], [], 0, NOW)
    expect(overview.overdue).toHaveLength(1)
    expect(overview.upcoming).toHaveLength(0)
  })

  test('a published or failed post is never called overdue, however old', () => {
    const old = '2020-01-01T00:00:00.000Z'
    const overview = summarise([
      row({ id: 'p', status: 'published', scheduled_for: old }),
      row({ id: 'f', status: 'failed', scheduled_for: old }),
    ], [], 0, NOW)

    expect(overview.overdue).toEqual([])
    expect(overview.failures.map((r) => r.id)).toEqual(['f'])
  })

  test('both lists come back soonest first', () => {
    const overview = summarise([
      row({ id: 'c', scheduled_for: '2026-09-09T20:00:00.000Z' }),
      row({ id: 'a', scheduled_for: '2026-09-09T14:00:00.000Z' }),
      row({ id: 'b', scheduled_for: '2026-09-09T16:00:00.000Z' }),
    ], [], 0, NOW)

    expect(overview.upcoming.map((r) => r.id)).toEqual(['a', 'b', 'c'])
  })

  test('every account that is not connected is surfaced, whatever the reason', () => {
    const overview = summarise([], [
      account({ id: 'ok' }),
      account({ id: 'gone', status: 'disconnected' }),
      account({ id: 'broken', status: 'error' }),
    ], 0, NOW)

    // Listing only 'disconnected' would hide an account in 'error', which fails
    // exactly the same way when something is scheduled to it.
    expect(overview.disconnected.map((a) => a.id)).toEqual(['gone', 'broken'])
  })

  test('a row with no time is neither upcoming nor overdue rather than crashing', () => {
    const overview = summarise([row({ scheduled_for: null })], [], 0, NOW)
    expect(overview.upcoming).toHaveLength(1)
    expect(overview.overdue).toHaveLength(0)
  })

  test('an empty business summarises to zeroes, not to undefined', () => {
    expect(summarise([], [], 0, NOW)).toEqual({
      scheduled: 0, published: 0, failed: 0, drafts: 0,
      upcoming: [], overdue: [], failures: [], disconnected: [],
    })
  })
})

describe('grouping the calendar by day', () => {
  test('a day is a UTC day, so late-evening posts do not drift into tomorrow', () => {
    expect(dayKeyUtc('2026-09-09T23:30:00.000Z')).toBe('2026-09-09')
    expect(dayKeyUtc('2026-09-10T00:30:00.000Z')).toBe('2026-09-10')
  })

  test('junk groups under an empty key rather than throwing mid-render', () => {
    expect(dayKeyUtc(null)).toBe('')
    expect(dayKeyUtc('not a date')).toBe('')
  })

  test('the heading is fixed to UTC, so it agrees with the times beneath it', () => {
    expect(formatDayUtc('2026-09-09')).toBe('Wednesday 9 September 2026')
  })

  test('a key that is not a date is shown as-is rather than as "Invalid Date"', () => {
    expect(formatDayUtc('')).toBe('')
  })
})

describe('showing an existing time back to the operator', () => {
  test('round-trips into the value a datetime-local input expects', () => {
    expect(toScheduleValue('2026-09-09T15:30:00.000Z')).toBe('2026-09-09T15:30')
    expect(toScheduleValue(null)).toBe('')
    expect(toScheduleValue('nonsense')).toBe('')
  })

  test('says how far away something is, in both directions', () => {
    expect(relativeToNow('2026-09-09T15:00:00.000Z', NOW)).toBe('in 3 hours')
    expect(relativeToNow('2026-09-09T11:30:00.000Z', NOW)).toBe('30 minutes ago')
    expect(relativeToNow('2026-09-11T12:00:00.000Z', NOW)).toBe('in 2 days')
    expect(relativeToNow('2026-09-09T12:00:00.000Z', NOW)).toBe('now')
  })

  test('uses the singular when there is one of something', () => {
    expect(relativeToNow('2026-09-09T13:00:00.000Z', NOW)).toBe('in 1 hour')
    expect(relativeToNow('2026-09-08T12:00:00.000Z', NOW)).toBe('1 day ago')
  })
})
