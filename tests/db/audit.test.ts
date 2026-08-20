/**
 * QUALITY BAR #4: every mutating action writes an audit_log row.
 *
 * The audit trail is produced by database triggers rather than by application code,
 * so it cannot be forgotten: a write from the web app, a worker, psql or a future
 * connector all land in the same place.
 */
import { beforeAll, afterAll, describe, expect, test } from 'vitest'
import { asAdmin, asUser, dropDatabase, expectRejected, freshDatabase } from './helpers'

const DB = 'postdeck_audit_test'
let url: string
const ALICE = '11111111-1111-1111-1111-111111111111'
let businessA: string

beforeAll(async () => {
  url = await freshDatabase(DB)
  await asAdmin(url, async (q) => {
    await q(`insert into auth.users (id, email) values ($1,'alice@example.com')`, [ALICE])
    const a = await q(`insert into public.businesses (name) values ('Tenant A') returning id`)
    businessA = a.rows[0].id
    await q(`insert into public.business_members (business_id, user_id, role) values ($1,$2,'owner')`, [businessA, ALICE])
  })
}, 60_000)

afterAll(async () => { await dropDatabase(DB) })

/** Counts audit rows, then runs `work`, then returns the rows that appeared. */
async function auditRowsFor(work: () => Promise<void>) {
  const before = await asAdmin(url, async (q) => (await q(`select coalesce(max(id),0) as m from public.audit_log`)).rows[0].m)
  await work()
  return asAdmin(url, async (q) =>
    (await q(`select * from public.audit_log where id > $1 order by id`, [before])).rows)
}

describe('every insert, update and delete is recorded', () => {
  test('inserting a post writes one audit row naming the actor and business', async () => {
    const rows = await auditRowsFor(async () => {
      await asUser(url, ALICE, 'aal2', async (q) => {
        await q(`insert into public.posts (business_id, body) values ($1,'{"text":"hello"}')`, [businessA])
      })
    })
    expect(rows).toHaveLength(1)
    expect(rows[0].action).toBe('posts.insert')
    expect(rows[0].actor_user_id).toBe(ALICE)
    expect(rows[0].business_id).toBe(businessA)
    expect(rows[0].target_type).toBe('posts')
    expect(rows[0].target_id).toBeTruthy()
  })

  test('updating a post records which columns changed, but not their values', async () => {
    let postId: string
    await asUser(url, ALICE, 'aal2', async (q) => {
      postId = (await q(`insert into public.posts (business_id, body) values ($1,'{"text":"v1"}') returning id`, [businessA])).rows[0].id
    })
    const rows = await auditRowsFor(async () => {
      await asUser(url, ALICE, 'aal2', async (q) => {
        await q(`update public.posts set status='approved' where id=$1`, [postId])
      })
    })
    expect(rows).toHaveLength(1)
    expect(rows[0].action).toBe('posts.update')
    expect(rows[0].metadata.changed_columns).toEqual(['status'])
    // The post body must never be copied into the audit table.
    expect(JSON.stringify(rows[0].metadata)).not.toContain('v1')
  })

  test('deleting a post writes a delete row', async () => {
    let postId: string
    await asUser(url, ALICE, 'aal2', async (q) => {
      postId = (await q(`insert into public.posts (business_id, body) values ($1,'{}') returning id`, [businessA])).rows[0].id
    })
    const rows = await auditRowsFor(async () => {
      await asUser(url, ALICE, 'aal2', async (q) => { await q(`delete from public.posts where id=$1`, [postId]) })
    })
    expect(rows.map((r) => r.action)).toEqual(['posts.delete'])
  })

  test.each([
    ['social_accounts', `insert into public.social_accounts (business_id, platform, label) values ($1,'tiktok','t')`],
    ['business_members', `insert into public.business_members (business_id, user_id, role) values ($1,'33333333-3333-3333-3333-333333333333','viewer')`],
  ])('inserting into %s is audited', async (table, sql) => {
    await asAdmin(url, async (q) => {
      await q(`insert into auth.users (id, email) values ('33333333-3333-3333-3333-333333333333','c@example.com') on conflict do nothing`)
    })
    const rows = await auditRowsFor(async () => {
      await asUser(url, ALICE, 'aal2', async (q) => { await q(sql, [businessA]) })
    })
    expect(rows.some((r) => r.action === `${table}.insert` && r.business_id === businessA)).toBe(true)
  })

  test('scheduling a post is audited against the business of its parent post', async () => {
    let postId: string, accountId: string
    await asUser(url, ALICE, 'aal2', async (q) => {
      postId = (await q(`insert into public.posts (business_id, body) values ($1,'{}') returning id`, [businessA])).rows[0].id
      accountId = (await q(`insert into public.social_accounts (business_id, platform, label) values ($1,'x','x') returning id`, [businessA])).rows[0].id
    })
    const rows = await auditRowsFor(async () => {
      await asUser(url, ALICE, 'aal2', async (q) => {
        await q(`insert into public.scheduled_posts (post_id, social_account_id, scheduled_for) values ($1,$2, now())`, [postId, accountId])
      })
    })
    const row = rows.find((r) => r.action === 'scheduled_posts.insert')
    expect(row).toBeTruthy()
    expect(row.business_id).toBe(businessA)
  })
})

describe('application-level actions are recorded through app.write_audit', () => {
  test('a business switch writes an audit row stamped with the real actor and IP', async () => {
    const rows = await auditRowsFor(async () => {
      await asUser(url, ALICE, 'aal2', async (q) => {
        await q(`select app.write_audit('auth.business_switch', $1, 'business', $2, '{"from":null}'::jsonb, '203.0.113.7'::inet)`, [businessA, businessA])
      })
    })
    expect(rows).toHaveLength(1)
    expect(rows[0].action).toBe('auth.business_switch')
    expect(rows[0].actor_user_id).toBe(ALICE)
    expect(rows[0].ip).toBe('203.0.113.7')
  })

  test('the actor is taken from the JWT, so a caller cannot log an action as someone else', async () => {
    const rows = await auditRowsFor(async () => {
      await asUser(url, ALICE, 'aal2', async (q) => {
        await q(`select app.write_audit('auth.login', $1)`, [businessA])
      })
    })
    // app.write_audit has no actor parameter at all -- it reads auth.uid() itself.
    expect(rows[0].actor_user_id).toBe(ALICE)
  })
})

describe('the audit trail cannot be rewritten', () => {
  test('nobody can update an audit row, not even with full privileges', async () => {
    await asAdmin(url, async (q) => {
      const err = await expectRejected(() => q(`update public.audit_log set action='tampered' where id = (select min(id) from public.audit_log)`))
      expect(err.message).toMatch(/append-only/i)
    })
  })

  test('nobody can delete an audit row, not even with full privileges', async () => {
    await asAdmin(url, async (q) => {
      const err = await expectRejected(() => q(`delete from public.audit_log where id = (select min(id) from public.audit_log)`))
      expect(err.message).toMatch(/append-only/i)
    })
  })

  test('a signed-in user has no INSERT privilege on audit_log', async () => {
    await asUser(url, ALICE, 'aal2', async (q) => {
      const err = await expectRejected(() =>
        q(`insert into public.audit_log (actor_user_id, action) values ($1,'forged')`, [ALICE]))
      expect(err.message).toMatch(/permission denied/i)
    })
  })
})
