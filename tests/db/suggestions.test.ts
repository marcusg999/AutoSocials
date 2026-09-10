/**
 * The assistant's table, under the same rules as everything else.
 *
 * A suggestion is generated from one business's draft and is about that business.
 * It arrives through a new code path — an action that calls a third party and
 * writes what comes back — so the question worth asking of `0016` is not whether
 * the feature works but whether the boundary held while a new table was added
 * next to it.
 *
 * The second property here is narrower and specific to this table: there is no
 * UPDATE grant at all. A suggestion is the record of what the model said, and a
 * row that can be edited in place cannot answer "did the model write this, or did
 * I?" — which is the only question this table exists to answer.
 */
import { beforeAll, afterAll, beforeEach, describe, expect, test } from 'vitest'
import { asAdmin, asUser, dropDatabase, expectRejected, freshDatabase } from './helpers'

const DB = 'postdeck_suggestions_test'
let url: string
const ALICE = '11111111-1111-1111-1111-111111111111'
const BOB = '22222222-2222-2222-2222-222222222222'
let businessA: string
let businessB: string

async function seedSuggestion(businessId: string, author: string, text = 'a suggestion') {
  return await asAdmin(url, async (q) => (await q(
    `insert into public.post_suggestions (business_id, created_by, suggestion, model)
     values ($1,$2,$3,'claude-opus-5') returning id`,
    [businessId, author, text])).rows[0].id as string)
}

beforeAll(async () => {
  url = await freshDatabase(DB)
  await asAdmin(url, async (q) => {
    await q(`insert into auth.users (id, email) values ($1,'alice@example.com')`, [ALICE])
    await q(`insert into auth.users (id, email) values ($1,'bob@example.com')`, [BOB])
    businessA = (await q(
      `insert into public.businesses (name) values ('Tenant A') returning id`)).rows[0].id
    businessB = (await q(
      `insert into public.businesses (name) values ('Tenant B') returning id`)).rows[0].id
    await q(`insert into public.business_members (business_id, user_id, role) values ($1,$2,'owner')`,
      [businessA, ALICE])
    await q(`insert into public.business_members (business_id, user_id, role) values ($1,$2,'owner')`,
      [businessB, BOB])
  })
}, 60_000)

afterAll(async () => { await dropDatabase(DB) })

beforeEach(async () => {
  await asAdmin(url, async (q) => { await q(`delete from public.post_suggestions`) })
})

describe('tenancy', () => {
  test('an owner sees their own business\'s suggestions', async () => {
    await seedSuggestion(businessA, ALICE, 'for tenant A')

    const rows = await asUser(url, ALICE, 'aal2', async (q) =>
      (await q(`select suggestion from public.post_suggestions`)).rows)

    expect(rows.map((r) => r.suggestion)).toEqual(['for tenant A'])
  })

  test('a member of another business reads zero rows, not an error', async () => {
    await seedSuggestion(businessA, ALICE, 'for tenant A')

    const rows = await asUser(url, BOB, 'aal2', async (q) =>
      (await q(`select * from public.post_suggestions`)).rows)

    expect(rows).toEqual([])
  })

  test('a suggestion cannot be written into someone else\'s business', async () => {
    const error = await expectRejected(() => asUser(url, BOB, 'aal2', async (q) => {
      await q(
        `insert into public.post_suggestions (business_id, created_by, suggestion, model)
         values ($1,$2,'planted','claude-opus-5')`, [businessA, BOB])
    }))
    expect(error.message).toMatch(/row-level security/i)
  })

  test('a suggestion cannot be stamped with someone else\'s authorship', async () => {
    // Same reason posts.created_by is pinned: a forged author makes the audit
    // trail lie, and created_by is a foreign key into auth.users, so the error
    // message would otherwise answer "does this user exist?".
    const error = await expectRejected(() => asUser(url, ALICE, 'aal2', async (q) => {
      await q(
        `insert into public.post_suggestions (business_id, created_by, suggestion, model)
         values ($1,$2,'not mine','claude-opus-5')`, [businessA, BOB])
    }))
    expect(error.message).toMatch(/row-level security/i)
  })

  test('an outsider cannot delete what they cannot see', async () => {
    const id = await seedSuggestion(businessA, ALICE)

    await asUser(url, BOB, 'aal2', async (q) => {
      await q(`delete from public.post_suggestions where id = $1`, [id])
    })

    const left = await asAdmin(url, async (q) =>
      (await q(`select 1 from public.post_suggestions where id = $1`, [id])).rowCount)
    expect(left).toBe(1)
  })

  test('a password-only session sees nothing, like every other table', async () => {
    await seedSuggestion(businessA, ALICE)

    const rows = await asUser(url, ALICE, 'aal1', async (q) =>
      (await q(`select * from public.post_suggestions`)).rows)

    expect(rows).toEqual([])
  })
})

describe('a suggestion is a record, not a draft', () => {
  test('nobody can edit one in place, not even its author', async () => {
    const id = await seedSuggestion(businessA, ALICE, 'what the model said')

    const error = await expectRejected(() => asUser(url, ALICE, 'aal2', async (q) => {
      await q(`update public.post_suggestions set suggestion = 'what I wish it said' where id = $1`,
        [id])
    }))
    expect(error.message).toMatch(/permission denied/i)
  })

  // Separate test on purpose: two refusals in one transaction would see the
  // second rejected because the first aborted it, which passes for the wrong
  // reason and would keep passing with the grant restored.
  test('the model it was attributed to cannot be rewritten either', async () => {
    const id = await seedSuggestion(businessA, ALICE)

    const error = await expectRejected(() => asUser(url, ALICE, 'aal2', async (q) => {
      await q(`update public.post_suggestions set model = 'something-cheaper' where id = $1`, [id])
    }))
    expect(error.message).toMatch(/permission denied/i)
  })

  test('but it can be thrown away, because keeping every one forever is not the point', async () => {
    const id = await seedSuggestion(businessA, ALICE)

    await asUser(url, ALICE, 'aal2', async (q) => {
      await q(`delete from public.post_suggestions where id = $1`, [id])
    })

    const left = await asAdmin(url, async (q) =>
      (await q(`select 1 from public.post_suggestions where id = $1`, [id])).rowCount)
    expect(left).toBe(0)
  })
})

describe('the audit trail', () => {
  test('covers this table like every other business-scoped one', async () => {
    // 0007 attached the trigger by name to the five tables that existed then. A
    // sixth table added later is exactly the case that list cannot notice, so
    // 0016 attaches it and this asserts it actually fires.
    const id = await seedSuggestion(businessA, ALICE)
    await asAdmin(url, async (q) => {
      await q(`delete from public.post_suggestions where id = $1`, [id])
    })

    const actions = await asAdmin(url, async (q) => (await q(
      `select action from public.audit_log
        where target_type = 'post_suggestions' and target_id = $1
        order by created_at`, [id])).rows.map((r) => r.action))

    expect(actions).toEqual(['post_suggestions.insert', 'post_suggestions.delete'])
  })
})
