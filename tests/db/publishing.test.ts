/**
 * The claim, which is the part of publishing that cannot be fixed afterwards.
 *
 * Everything else in this phase is recoverable. A post that fails to go out can be
 * retried; a wrong caption can be deleted. A post published TWICE cannot be
 * un-seen, so "two workers never take the same row" is the property this file
 * exists to hold, and it is tested with two real concurrent transactions rather
 * than by reading the SQL and believing it.
 *
 * The second property is the one the narrowed grant buys: an owner cannot write
 * "published" onto a row themselves. The audit trail and the calendar are the only
 * places the operator learns what happened, and a forged row would corrupt both.
 */
import { beforeAll, afterAll, beforeEach, describe, expect, test } from 'vitest'
import { Client } from 'pg'
import { asAdmin, asUser, dropDatabase, expectRejected, freshDatabase, urlFor } from './helpers'

const DB = 'postdeck_publishing_test'
let url: string
const ALICE = '11111111-1111-1111-1111-111111111111'
let businessA: string
let accountId: string
let postId: string

/** Schedule one post in the past, so it is due the moment a worker looks. */
async function scheduleDuePost(): Promise<string> {
  return await asAdmin(url, async (q) => {
    const { rows } = await q(
      `insert into public.scheduled_posts (post_id, social_account_id, business_id, scheduled_for)
       values ($1,$2,$3, now() - interval '1 minute') returning id`,
      [postId, accountId, businessA])
    return rows[0].id as string
  })
}

beforeAll(async () => {
  url = await freshDatabase(DB)
  await asAdmin(url, async (q) => {
    await q(`insert into auth.users (id, email) values ($1,'alice@example.com')`, [ALICE])
    businessA = (await q(`insert into public.businesses (name) values ('Tenant A') returning id`)).rows[0].id
    await q(`insert into public.business_members (business_id, user_id, role) values ($1,$2,'owner')`,
      [businessA, ALICE])
    accountId = (await q(
      `insert into public.social_accounts (business_id, platform, label, provider_account_ref, status)
       values ($1,'facebook','FB page','page-1','connected') returning id`, [businessA])).rows[0].id
    postId = (await q(
      `insert into public.posts (business_id, created_by, body)
       values ($1,$2,'{"text":"hello"}'::jsonb) returning id`, [businessA, ALICE])).rows[0].id
  })
}, 60_000)

afterAll(async () => { await dropDatabase(DB) })

beforeEach(async () => {
  await asAdmin(url, async (q) => { await q(`delete from public.scheduled_posts`) })
})

describe('claiming', () => {
  test('returns a due row with everything the worker needs to publish it', async () => {
    const scheduledId = await scheduleDuePost()

    const claimed = await asAdmin(url, async (q) =>
      (await q(`select * from app.claim_due_scheduled_posts('worker-1')`)).rows)

    expect(claimed).toHaveLength(1)
    expect(claimed[0].scheduled_id).toBe(scheduledId)
    expect(claimed[0].platform).toBe('facebook')
    expect(claimed[0].provider_account_ref).toBe('page-1')
    expect(claimed[0].body).toEqual({ text: 'hello' })
    // The attempt just consumed, not the count before it.
    expect(claimed[0].attempts).toBe(1)
  })

  test('leaves a row that is not due yet', async () => {
    await asAdmin(url, async (q) => {
      await q(`insert into public.scheduled_posts (post_id, social_account_id, business_id, scheduled_for)
               values ($1,$2,$3, now() + interval '1 hour')`, [postId, accountId, businessA])
    })
    const claimed = await asAdmin(url, async (q) =>
      (await q(`select * from app.claim_due_scheduled_posts('worker-1')`)).rows)
    expect(claimed).toHaveLength(0)
  })

  test('leaves a due row whose account has been disconnected', async () => {
    await scheduleDuePost()
    await asAdmin(url, async (q) => {
      await q(`update public.social_accounts set status='disconnected' where id=$1`, [accountId])
    })

    const claimed = await asAdmin(url, async (q) =>
      (await q(`select * from app.claim_due_scheduled_posts('worker-1')`)).rows)
    expect(claimed).toHaveLength(0)

    // Still scheduled, not failed: reconnect the account and it goes out.
    await asAdmin(url, async (q) => {
      const row = (await q(`select status from public.scheduled_posts`)).rows[0]
      expect(row.status).toBe('scheduled')
      await q(`update public.social_accounts set status='connected' where id=$1`, [accountId])
    })
  })

  test('does not hand the same row to a second worker while the lease holds', async () => {
    await scheduleDuePost()

    const first = await asAdmin(url, async (q) =>
      (await q(`select * from app.claim_due_scheduled_posts('worker-1')`)).rows)
    const second = await asAdmin(url, async (q) =>
      (await q(`select * from app.claim_due_scheduled_posts('worker-2')`)).rows)

    expect(first).toHaveLength(1)
    expect(second).toHaveLength(0)
  })

  test('hands it back once the lease has expired, because that worker died', async () => {
    await scheduleDuePost()
    await asAdmin(url, async (q) => {
      await q(`select * from app.claim_due_scheduled_posts('worker-1')`)
      // The worker crashed. Its lock is long gone; only locked_until still holds
      // the row, and that is exactly what expiring it is for.
      await q(`update public.scheduled_posts set locked_until = now() - interval '1 second'`)
    })

    const retry = await asAdmin(url, async (q) =>
      (await q(`select * from app.claim_due_scheduled_posts('worker-2')`)).rows)
    expect(retry).toHaveLength(1)
    expect(retry[0].attempts).toBe(2)
  })

  /**
   * The one that matters. Two transactions open at once, both claiming, neither
   * committed until both have run — which is the only arrangement where SKIP
   * LOCKED is actually load-bearing. Run them sequentially and the lease alone
   * would pass the test while a genuinely concurrent pair still double-published.
   */
  test('two concurrent workers take disjoint sets, never the same row', async () => {
    const scheduled: string[] = []
    for (let i = 0; i < 6; i += 1) scheduled.push(await scheduleDuePost())

    const a = new Client({ connectionString: urlFor(DB) })
    const b = new Client({ connectionString: urlFor(DB) })
    await a.connect(); await b.connect()
    try {
      await a.query('begin'); await b.query('begin')

      // A claims first and holds its transaction open. B must skip A's locked rows
      // rather than block on them or take them.
      const takenByA = (await a.query(`select scheduled_id from app.claim_due_scheduled_posts('a', 3)`)).rows
      const takenByB = (await b.query(`select scheduled_id from app.claim_due_scheduled_posts('b', 3)`)).rows

      await a.query('commit'); await b.query('commit')

      const idsA = takenByA.map((r) => r.scheduled_id)
      const idsB = takenByB.map((r) => r.scheduled_id)
      expect(idsA).toHaveLength(3)
      expect(idsB).toHaveLength(3)
      expect(idsA.filter((id) => idsB.includes(id))).toEqual([])
      expect(new Set([...idsA, ...idsB]).size).toBe(6)
      expect([...idsA, ...idsB].sort()).toEqual([...scheduled].sort())
    } finally {
      await a.end(); await b.end()
    }
  })

  test('never leases more than the cap, however big a batch is asked for', async () => {
    for (let i = 0; i < 3; i += 1) await scheduleDuePost()
    const claimed = await asAdmin(url, async (q) =>
      (await q(`select * from app.claim_due_scheduled_posts('greedy', 1000000)`)).rows)
    // Capped at 100 by the function; only 3 exist, so all three, and no error.
    expect(claimed).toHaveLength(3)
  })
})

describe('completing', () => {
  test('success is terminal and records what the platform created', async () => {
    const scheduledId = await scheduleDuePost()
    await asAdmin(url, async (q) => {
      await q(`select * from app.claim_due_scheduled_posts('worker-1')`)
      await q(`select app.complete_scheduled_post($1, true, 'page-1_9876')`, [scheduledId])

      const row = (await q(`select * from public.scheduled_posts where id=$1`, [scheduledId])).rows[0]
      expect(row.status).toBe('published')
      expect(row.provider_post_ref).toBe('page-1_9876')
      expect(row.published_at).not.toBeNull()
      expect(row.locked_until).toBeNull()
      expect(row.last_error).toBeNull()
    })
  })

  test('a failure with attempts left releases the row and backs off', async () => {
    const scheduledId = await scheduleDuePost()
    await asAdmin(url, async (q) => {
      await q(`select * from app.claim_due_scheduled_posts('worker-1')`)
      await q(`select app.complete_scheduled_post($1, false, null, 'Meta rejected the request: rate limited')`,
        [scheduledId])

      const row = (await q(`select * from public.scheduled_posts where id=$1`, [scheduledId])).rows[0]
      expect(row.status).toBe('scheduled')
      expect(row.last_error).toMatch(/rate limited/)
      expect(row.locked_until).toBeNull()
      expect(new Date(row.next_attempt_at).getTime()).toBeGreaterThan(Date.now())
    })
  })

  test('a row that has run out of attempts fails for good', async () => {
    const scheduledId = await scheduleDuePost()
    await asAdmin(url, async (q) => {
      await q(`update public.scheduled_posts set attempts = 5 where id=$1`, [scheduledId])
      await q(`select app.complete_scheduled_post($1, false, null, 'still broken', 5)`, [scheduledId])

      const row = (await q(`select * from public.scheduled_posts where id=$1`, [scheduledId])).rows[0]
      expect(row.status).toBe('failed')
      expect(row.last_error).toBe('still broken')
    })
  })

  test('a failed row is not picked up again', async () => {
    const scheduledId = await scheduleDuePost()
    await asAdmin(url, async (q) => {
      await q(`update public.scheduled_posts set attempts = 5 where id=$1`, [scheduledId])
      await q(`select app.complete_scheduled_post($1, false, null, 'gone', 5)`, [scheduledId])
    })
    const claimed = await asAdmin(url, async (q) =>
      (await q(`select * from app.claim_due_scheduled_posts('worker-2')`)).rows)
    expect(claimed).toHaveLength(0)
  })

  test('provider error text is truncated before it is stored', async () => {
    const scheduledId = await scheduleDuePost()
    await asAdmin(url, async (q) => {
      await q(`select app.complete_scheduled_post($1, false, null, $2)`, [scheduledId, 'x'.repeat(5000)])
      const row = (await q(`select last_error from public.scheduled_posts where id=$1`, [scheduledId])).rows[0]
      expect(row.last_error.length).toBe(500)
    })
  })

  test('completing something that does not exist is an error, not a silent no-op', async () => {
    await asAdmin(url, async (q) => {
      const err = await expectRejected(() =>
        q(`select app.complete_scheduled_post('99999999-9999-4999-8999-999999999999', true)`))
      expect(err.message).toMatch(/no such scheduled post/i)
    })
  })
})

describe('a signed-in owner cannot do the worker\'s job', () => {
  test('cannot execute the claim function', async () => {
    await scheduleDuePost()
    await asUser(url, ALICE, 'aal2', async (q) => {
      const err = await expectRejected(() => q(`select * from app.claim_due_scheduled_posts('me')`))
      expect(err.message).toMatch(/permission denied/i)
    })
  })

  test('cannot execute the completion function', async () => {
    const scheduledId = await scheduleDuePost()
    await asUser(url, ALICE, 'aal2', async (q) => {
      const err = await expectRejected(() =>
        q(`select app.complete_scheduled_post($1, true, 'forged')`, [scheduledId]))
      expect(err.message).toMatch(/permission denied/i)
    })
  })

  /**
   * The reason 0014 narrowed the UPDATE grant. Before it, this succeeded: an owner
   * could write published_at onto their own row and produce a scheduled post that
   * claims to have gone out when nothing was ever sent.
   */
  test('cannot mark a row published by hand', async () => {
    const scheduledId = await scheduleDuePost()
    await asUser(url, ALICE, 'aal2', async (q) => {
      const err = await expectRejected(() =>
        q(`update public.scheduled_posts set status='published', published_at=now() where id=$1`,
          [scheduledId]))
      expect(err.message).toMatch(/permission denied/i)
    })
  })

  // One statement per session on purpose: the first refusal aborts the
  // transaction, so a second failing statement in the same block reports
  // "transaction is aborted" and would pass this test for the wrong reason.
  test('cannot write a provider_post_ref', async () => {
    const scheduledId = await scheduleDuePost()
    await asUser(url, ALICE, 'aal2', async (q) => {
      const err = await expectRejected(() =>
        q(`update public.scheduled_posts set provider_post_ref='fake' where id=$1`, [scheduledId]))
      expect(err.message).toMatch(/permission denied/i)
    })
  })

  test('cannot clear a recorded error', async () => {
    const scheduledId = await scheduleDuePost()
    await asUser(url, ALICE, 'aal2', async (q) => {
      const err = await expectRejected(() =>
        q(`update public.scheduled_posts set last_error=null where id=$1`, [scheduledId]))
      expect(err.message).toMatch(/permission denied/i)
    })
  })

  test('cannot steal a row from the worker by clearing its lease', async () => {
    const scheduledId = await scheduleDuePost()
    await asAdmin(url, async (q) => { await q(`select * from app.claim_due_scheduled_posts('worker-1')`) })
    await asUser(url, ALICE, 'aal2', async (q) => {
      const err = await expectRejected(() =>
        q(`update public.scheduled_posts set locked_until=null where id=$1`, [scheduledId]))
      expect(err.message).toMatch(/permission denied/i)
    })
  })

  test('but can still reschedule, which is the one thing they should be able to do', async () => {
    const scheduledId = await scheduleDuePost()
    await asUser(url, ALICE, 'aal2', async (q) => {
      await q(`update public.scheduled_posts set scheduled_for = now() + interval '2 days' where id=$1`,
        [scheduledId])
    })
    await asAdmin(url, async (q) => {
      const row = (await q(`select scheduled_for from public.scheduled_posts where id=$1`, [scheduledId])).rows[0]
      expect(new Date(row.scheduled_for).getTime()).toBeGreaterThan(Date.now())
    })
  })

  test('and can still cancel by deleting it', async () => {
    const scheduledId = await scheduleDuePost()
    await asUser(url, ALICE, 'aal2', async (q) => {
      await q(`delete from public.scheduled_posts where id=$1`, [scheduledId])
    })
    await asAdmin(url, async (q) => {
      expect((await q(`select * from public.scheduled_posts where id=$1`, [scheduledId])).rowCount).toBe(0)
    })
  })
})

describe('the audit trail', () => {
  test('every attempt is recorded by the trigger, not by the worker', async () => {
    const scheduledId = await scheduleDuePost()
    await asAdmin(url, async (q) => {
      // audit_log is append-only against every role including this one, so the
      // rows are counted for this scheduled post rather than cleared first. That
      // the delete is impossible is itself the Phase 1 guarantee working.
      await q(`select * from app.claim_due_scheduled_posts('worker-1')`)
      await q(`select app.complete_scheduled_post($1, true, 'page-1_1')`, [scheduledId])

      // Insert, claim, completion. All three come from the audit_changes trigger
      // 0007 already put on this table, in the same transaction as the change, so
      // they cannot describe a different row than the one that actually moved.
      const rows = (await q(
        `select action, metadata from public.audit_log where target_id = $1 order by created_at`,
        [scheduledId])).rows
      expect(rows.map((r) => r.action)).toEqual([
        'scheduled_posts.insert', 'scheduled_posts.update', 'scheduled_posts.update',
      ])
      // The worker's own columns are named in the trail, so "what changed and when"
      // is answerable without the worker being trusted to say so.
      expect(rows[1].metadata.changed_columns).toContain('locked_until')
      expect(rows[2].metadata.changed_columns).toContain('published_at')
    })
  })
})
