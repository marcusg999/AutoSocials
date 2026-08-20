/**
 * QUALITY BAR #1: a cross-tenant read returns zero rows and a cross-tenant write
 * is rejected. Proven here against a real Postgres with RLS switched on.
 *
 * The cast: ALICE belongs to Business A. MALLORY belongs to Business B and has a
 * perfectly valid, fully MFA'd session. Everything Mallory tries below is a request
 * she is genuinely authenticated for -- she is simply not a member of Business A.
 */
import { beforeAll, afterAll, describe, expect, test } from 'vitest'
import { asAdmin, asAnon, asUser, dropDatabase, expectRejected, freshDatabase } from './helpers'

const DB = 'postdeck_tenancy_test'
let url: string

const ALICE = '11111111-1111-1111-1111-111111111111'
const MALLORY = '22222222-2222-2222-2222-222222222222'

let businessA: string
let businessB: string
let postA: string
let accountA: string
let scheduledA: string

beforeAll(async () => {
  url = await freshDatabase(DB)
  await asAdmin(url, async (q) => {
    await q(`insert into auth.users (id, email) values ($1,'alice@example.com'), ($2,'mallory@example.com')`, [ALICE, MALLORY])

    const a = await q(`insert into public.businesses (name, timezone) values ('Tenant A','UTC') returning id`)
    const b = await q(`insert into public.businesses (name, timezone) values ('Tenant B','UTC') returning id`)
    businessA = a.rows[0].id
    businessB = b.rows[0].id

    await q(`insert into public.business_members (business_id, user_id, role) values ($1,$2,'owner')`, [businessA, ALICE])
    await q(`insert into public.business_members (business_id, user_id, role) values ($1,$2,'owner')`, [businessB, MALLORY])

    const p = await q(`insert into public.posts (business_id, created_by, body) values ($1,$2,'{"text":"tenant A secret"}') returning id`, [businessA, ALICE])
    postA = p.rows[0].id
    const acc = await q(`insert into public.social_accounts (business_id, platform, label) values ($1,'instagram','A insta') returning id`, [businessA])
    accountA = acc.rows[0].id
    const s = await q(`insert into public.scheduled_posts (post_id, social_account_id, business_id, scheduled_for) values ($1,$2,$3, now() + interval '1 day') returning id`, [postA, accountA, businessA])
    scheduledA = s.rows[0].id
  })
}, 60_000)

afterAll(async () => { await dropDatabase(DB) })

describe('a member sees their own tenant', () => {
  test('Alice can read her own business and its rows', async () => {
    await asUser(url, ALICE, 'aal2', async (q) => {
      expect((await q(`select id from public.businesses where id = $1`, [businessA])).rowCount).toBe(1)
      expect((await q(`select id from public.posts where business_id = $1`, [businessA])).rowCount).toBe(1)
      expect((await q(`select id from public.social_accounts where business_id = $1`, [businessA])).rowCount).toBe(1)
      expect((await q(`select id from public.scheduled_posts`)).rowCount).toBe(1)
    })
  })

  test('Alice can write inside her own business', async () => {
    await asUser(url, ALICE, 'aal2', async (q) => {
      const r = await q(`insert into public.posts (business_id, created_by, body) values ($1,$2,'{"text":"mine"}') returning id`, [businessA, ALICE])
      expect(r.rowCount).toBe(1)
    })
  })
})

describe('QUALITY BAR: a cross-tenant read returns zero rows', () => {
  test('Mallory sees no businesses she is not a member of', async () => {
    await asUser(url, MALLORY, 'aal2', async (q) => {
      const r = await q(`select id from public.businesses where id = $1`, [businessA])
      expect(r.rowCount).toBe(0)
    })
  })

  test.each([
    ['business_members', `select * from public.business_members`],
    ['social_accounts',  `select * from public.social_accounts`],
    ['posts',            `select * from public.posts`],
    ['scheduled_posts',  `select * from public.scheduled_posts`],
    ['audit_log',        `select * from public.audit_log`],
  ])('Mallory sees zero of Alice\'s rows in %s', async (_table, sql) => {
    await asUser(url, MALLORY, 'aal2', async (q) => {
      const rows = (await q(sql)).rows
      const leaked = rows.filter((r) => r.business_id === businessA || r.id === postA || r.id === accountA || r.id === scheduledA)
      expect(leaked).toEqual([])
    })
  })

  test('an unqualified SELECT * leaks nothing across tenants', async () => {
    await asUser(url, MALLORY, 'aal2', async (q) => {
      const posts = await q(`select * from public.posts`)
      expect(posts.rows.every((r) => r.business_id === businessB)).toBe(true)
      const text = JSON.stringify(posts.rows)
      expect(text).not.toContain('tenant A secret')
    })
  })

  test('a signed-out visitor reads nothing at all', async () => {
    await asAnon(url, async (q) => {
      // `anon` holds no table privileges, so the read is refused outright.
      const err = await expectRejected(() => q(`select * from public.posts`))
      expect(err.message).toMatch(/permission denied/i)
    })
  })
})

describe('QUALITY BAR: a cross-tenant write is rejected', () => {
  test('Mallory cannot create a post inside Alice\'s business', async () => {
    await asUser(url, MALLORY, 'aal2', async (q) => {
      const err = await expectRejected(() =>
        q(`insert into public.posts (business_id, created_by, body) values ($1,$2,'{"text":"intrusion"}')`, [businessA, MALLORY]))
      expect(err.message).toMatch(/row-level security/i)
    })
  })

  test('Mallory cannot connect a social account to Alice\'s business', async () => {
    await asUser(url, MALLORY, 'aal2', async (q) => {
      const err = await expectRejected(() =>
        q(`insert into public.social_accounts (business_id, platform, label) values ($1,'x','stolen')`, [businessA]))
      expect(err.message).toMatch(/row-level security/i)
    })
  })

  test('Mallory cannot add herself to Alice\'s business — nor to her own', async () => {
    // business_members is read-only from the app in Phase 1, so this is refused by
    // the grant before RLS is consulted. That also closes the oracle the insert
    // used to provide: user_id is a foreign key into auth.users, so a failed insert
    // used to reveal whether an arbitrary account existed.
    await asUser(url, MALLORY, 'aal2', async (q) => {
      // Savepoints: a rejected statement poisons the surrounding transaction, so
      // without these the second attempt reports "transaction aborted" rather than
      // its own error.
      await q(`savepoint s`)
      const intoTheirs = await expectRejected(() =>
        q(`insert into public.business_members (business_id, user_id, role) values ($1,$2,'owner')`, [businessA, MALLORY]))
      expect(intoTheirs.message).toMatch(/permission denied/i)
      await q(`rollback to savepoint s`)

      const intoOwn = await expectRejected(() =>
        q(`insert into public.business_members (business_id, user_id, role) values ($1,$2,'viewer')`, [businessB, ALICE]))
      expect(intoOwn.message).toMatch(/permission denied/i)
      await q(`rollback to savepoint s`)
    })
  })

  test('Mallory cannot update or delete Alice\'s post (it is invisible, so nothing changes)', async () => {
    await asUser(url, MALLORY, 'aal2', async (q) => {
      expect((await q(`update public.posts set status='published' where id=$1`, [postA])).rowCount).toBe(0)
      expect((await q(`delete from public.posts where id=$1`, [postA])).rowCount).toBe(0)
    })
    await asAdmin(url, async (q) => {
      const r = await q(`select status from public.posts where id=$1`, [postA])
      expect(r.rows[0].status).toBe('draft')
    })
  })

  test('Mallory cannot move her own post into Alice\'s business', async () => {
    let mallorysPost: string
    await asUser(url, MALLORY, 'aal2', async (q) => {
      const r = await q(`insert into public.posts (business_id, created_by, body) values ($1,$2,'{}') returning id`, [businessB, MALLORY])
      mallorysPost = r.rows[0].id
      const err = await expectRejected(() =>
        q(`update public.posts set business_id=$1 where id=$2`, [businessA, mallorysPost]))
      // business_id is outside the column-level UPDATE grant, so this is refused
      // before RLS is even consulted. Denied earlier is denied better.
      expect(err.message).toMatch(/permission denied|row-level security/i)
    })
  })

  test('Mallory cannot aim her own post at Alice\'s connected account', async () => {
    // The subtle one: both halves of scheduled_posts must belong to the same tenant,
    // or you could publish to someone else's Instagram from your own post.
    await asUser(url, MALLORY, 'aal2', async (q) => {
      const p = await q(`insert into public.posts (business_id, created_by, body) values ($1,$2,'{}') returning id`, [businessB, MALLORY])
      const err = await expectRejected(() =>
        q(`insert into public.scheduled_posts (post_id, social_account_id, business_id, scheduled_for) values ($1,$2,$3, now())`,
          [p.rows[0].id, accountA, businessB]))
      expect(err.message).toMatch(/row-level security/i)
    })
  })

  test('Mallory cannot forge an audit entry', async () => {
    await asUser(url, MALLORY, 'aal2', async (q) => {
      const err = await expectRejected(() =>
        q(`insert into public.audit_log (actor_user_id, business_id, action) values ($1,$2,'fake.action')`, [ALICE, businessA]))
      expect(err.message).toMatch(/permission denied|row-level security/i)
    })
  })
})

describe('the RLS helper functions do not leak tenant information', () => {
  test('Mallory cannot use a helper to turn a guessed post id into a business id', async () => {
    await asUser(url, MALLORY, 'aal2', async (q) => {
      const err = await expectRejected(() =>
        q(`select app.business_of_post_for_audit($1)`, [postA]))
      expect(err.message).toMatch(/permission denied/i)
    })
  })

  test('the helpers Mallory CAN call answer only yes/no, and answer "no"', async () => {
    await asUser(url, MALLORY, 'aal2', async (q) => {
      expect((await q(`select app.post_belongs_to($1,$2) as v`, [postA, businessB])).rows[0].v).toBe(false)
      expect((await q(`select app.account_belongs_to($1,$2) as v`, [accountA, businessB])).rows[0].v).toBe(false)
      expect((await q(`select app.is_member_of($1) as v`, [businessA])).rows[0].v).toBe(false)
    })
  })

  test('a signed-out visitor cannot execute any helper in the app schema', async () => {
    await asAnon(url, async (q) => {
      const err = await expectRejected(() => q(`select app.is_member_of($1)`, [businessA]))
      expect(err.message).toMatch(/permission denied/i)
    })
  })
})
