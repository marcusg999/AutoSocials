/**
 * When a post goes out.
 *
 * `<input type="datetime-local">` submits "2026-09-09T14:30" with no timezone at
 * all, and the obvious `new Date(value)` reads that in whatever zone the SERVER
 * happens to be in — so the same form, submitted by the same person, schedules a
 * different moment depending on where the app is deployed and whether the host is
 * on DST. That is a silent, once-a-year kind of wrong.
 *
 * So the string is parsed as UTC, explicitly, and every time this app displays is
 * displayed in UTC. One rule, stated on the form and on the calendar, with no
 * library and no ambiguity. The cost is real and is written down: someone in
 * California scheduling "09:00" is scheduling 09:00 UTC, which is 1am for them.
 */

const DATETIME_LOCAL = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/

/** Returns the instant, or null if the browser sent something unparseable. */
export function parseScheduledFor(value: string): Date | null {
  const match = DATETIME_LOCAL.exec(value.trim())
  if (!match) return null

  const [, year, month, day, hour, minute, second] = match
  const stamp = Date.UTC(
    Number(year), Number(month) - 1, Number(day),
    Number(hour), Number(minute), Number(second ?? '0'))
  const parsed = new Date(stamp)

  // Date.UTC rolls invalid components over rather than rejecting them: month 13
  // becomes January of the next year, 31 February becomes 3 March. Round-tripping
  // catches that, so "2026-02-31T09:00" is refused instead of silently moving.
  if (parsed.getUTCMonth() !== Number(month) - 1) return null
  if (parsed.getUTCDate() !== Number(day)) return null
  if (parsed.getUTCHours() !== Number(hour)) return null

  return parsed
}

/** How this app writes an instant, everywhere it shows one. */
export function formatUtc(value: string | Date | null): string {
  if (!value) return '—'
  const date = typeof value === 'string' ? new Date(value) : value
  if (Number.isNaN(date.getTime())) return '—'
  return `${date.toISOString().slice(0, 16).replace('T', ' ')} UTC`
}

/** A sensible default for the form: an hour from now, to the minute, in UTC. */
export function defaultScheduleValue(now: Date = new Date()): string {
  const later = new Date(now.getTime() + 60 * 60 * 1000)
  return later.toISOString().slice(0, 16)
}
