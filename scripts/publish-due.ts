/**
 * The worker entry point. One pass, then exit.
 *
 *   npm run publish:due
 *
 * Deliberately a single pass rather than a daemon with its own timer. Whatever
 * runs this — Railway's scheduler, cron, a person at a terminal — already knows how
 * to repeat something on an interval, and a process that exits is far easier to
 * reason about than one that is supposed to still be alive. Two of these running at
 * once is safe by construction: the claim is what makes it safe, not the schedule.
 *
 * It needs SUPABASE_SERVICE_ROLE_KEY, so it runs on a server you control and never
 * anywhere near a browser.
 */
import { publishDuePosts } from '@/lib/publishing/service'

async function main(): Promise<void> {
  const batch = Number(process.env.PUBLISH_BATCH ?? '10')

  const result = await publishDuePosts({
    batch: Number.isFinite(batch) ? batch : 10,
  })

  // One line, parseable, no post content in it. Worker logs are the least
  // controlled place output goes.
  console.log(
    `publish-due: claimed=${result.claimed} published=${result.published} failed=${result.failed}`)

  // A failed post is not a failed RUN — the row is recorded, will be retried, and
  // the operator can see it on the calendar. Exiting non-zero here would make a
  // scheduler alert on something the system already handled.
}

main().catch((error: unknown) => {
  console.error(`publish-due failed: ${error instanceof Error ? error.message : String(error)}`)
  process.exitCode = 1
})
