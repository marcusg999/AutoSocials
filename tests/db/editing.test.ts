/**
 * Editing a post, and where that stops being allowed.
 *
 * Phase 4 makes posts editable from the browser: a draft can be rewritten, saved
 * again, thrown away. `authenticated` holds `update (status, body) on posts`, and
 * for a draft that is exactly right.
 *
 * It stops being right the moment a post has gone out. The row is then the local
 * record of something other people can see, and the two ways to corrupt that
 * record — rewrite the body, or delete the post and cascade away the
 * scheduled_posts row holding published_at — both run through grants the operator
 * legitimately holds. That is what 0015's trigger is for, and what this file
 * proves: not that the trigger exists, but that each of those two writes is
 * refused while the same write on a draft still succeeds.
 */
import { beforeAll, afterAll, beforeEach, describe, expect, test } from 'vitest'
import { asAdmin, asUser, dropDatabase, expectRejected, freshDatabase } from './helpers'

const DB = 'postdeck_editing_test'
let url: string
const ALICE = '11111111-1111-1111-1111-111111111111'
let businessA: string
let accountId: string

/** A post with one scheduled row, left in whatever state the test needs. */
async function makePost(status: 'scheduled' | 'published' | 'failed'): Promise<string> {
  return await asAdmin(url, async (q) => {
    const postId = (await q(
      `insert into public.posts (business_id, created_by, status, body)
       values ($1,$2,'scheduled','{"text":"hello"}'::jsonb) returning id`,
      [businessA, ALICE])).rows[0].id as string

    await q(
      `insert into public.scheduled_posts
         (post_id, social_account_id, business_id, scheduled_for, status, published_at)
       values ($1,$2,$3, now(), $4::public.post_status, $5)`,
      [postId, accountId, businessA, status, status === 'published' ? new Date() : null])

    return postId
  })
}

async function makeDraft(): Promise<string> {
  return await asAdmin(url, async (q) => (await q(
    `insert into public.posts (business_id, created_by, status, body)
     values ($1,$2,'draft','{"text":"a draft"}'::jsonb) returning id`,
    [businessA, ALICE])).rows[0].id as string)
}

beforeAll(async () => {
  url = await freshDatabase(DB)
  await asAdmin(url, async (q) => {
    await q(`insert into auth.users (id, email) values ($1,'alice@example.com')`, [ALICE])
    businessA = (await q(
      `insert into public.businesses (name) values ('Tenant A') returning id`)).rows[0].id
    await q(`insert into public.business_members (business_id, user_id, role) values ($1,$2,'owner')`,
      [businessA, ALICE])
    accountId = (await q(
      `insert into public.social_accounts (business_id, platform, label, provider_account_ref, status)
       values ($1,'facebook','FB page','page-1','connected') returning id`,
      [businessA])).rows[0].id
  })
}, 60_000)

afterAll(async () => { await dropDatabase(DB) })

beforeEach(async () => {
  await asAdmin(url, async (q) => {
    await q(`delete from public.scheduled_posts`)
    await q(`delete from public.posts`)
  })
})

describe('a draft', () => {
  test('can be rewritten by its owner', async () => {
    const postId = await makeDraft()

    await asUser(url, ALICE, 'aal2', async (q) => {
      await q(`update public.posts set body = '{"text":"rewritten"}'::jsonb where id = $1`, [postId])
    })

    const body = await asAdmin(url, async (q) =>
      (await q(`select body from public.posts where id = $1`, [postId])).rows[0].body)
    expect(body).toEqual({ text: 'rewritten' })
  })

  test('can be promoted to scheduled, which is what scheduling one does', async () => {
    const postId = await makeDraft()

    await asUser(url, ALICE, 'aal2', async (q) => {
      await q(`update public.posts set status = 'scheduled' where id = $1`, [postId])
    })

    const status = await asAdmin(url, async (q) =>
      (await q(`select status from public.posts where id = $1`, [postId])).rows[0].status)
    expect(status).toBe('scheduled')
  })

  test('can be deleted', async () => {
    const postId = await makeDraft()

    await asUser(url, ALICE, 'aal2', async (q) => {
      await q(`delete from public.posts where id = $1`, [postId])
    })

    const left = await asAdmin(url, async (q) =>
      (await q(`select 1 from public.posts where id = $1`, [postId])).rowCount)
    expect(left).toBe(0)
  })
})

describe('a post that is scheduled but has not gone out', () => {
  test('is still editable, because nothing has been published yet', async () => {
    const postId = await makePost('scheduled')

    await asUser(url, ALICE, 'aal2', async (q) => {
      await q(`update public.posts set body = '{"text":"fixed a typo"}'::jsonb where id = $1`,
        [postId])
    })

    const body = await asAdmin(url, async (q) =>
      (await q(`select body from public.posts where id = $1`, [postId])).rows[0].body)
    expect(body).toEqual({ text: 'fixed a typo' })
  })

  test('is still editable after an attempt FAILED, so a bad post can be fixed', async () => {
    // The useful case: Meta rejected it, the operator corrects the caption. A
    // failure means nothing is live, so there is nothing to be inconsistent with.
    const postId = await makePost('failed')

    await asUser(url, ALICE, 'aal2', async (q) => {
      await q(`update public.posts set body = '{"text":"corrected"}'::jsonb where id = $1`, [postId])
    })

    const body = await asAdmin(url, async (q) =>
      (await q(`select body from public.posts where id = $1`, [postId])).rows[0].body)
    expect(body).toEqual({ text: 'corrected' })
  })
})

describe('a post that has been published', () => {
  test('cannot have its body rewritten', async () => {
    const postId = await makePost('published')

    const error = await expectRejected(() => asUser(url, ALICE, 'aal2', async (q) => {
      await q(`update public.posts set body = '{"text":"never said this"}'::jsonb where id = $1`,
        [postId])
    }))
    expect(error.message).toMatch(/already been published/i)
  })

  // Separate test on purpose. Two refusals in one transaction would see the second
  // rejected because the first aborted it, which passes for the wrong reason and
  // would keep passing with the trigger removed.
  test('cannot have its status changed', async () => {
    const postId = await makePost('published')

    const error = await expectRejected(() => asUser(url, ALICE, 'aal2', async (q) => {
      await q(`update public.posts set status = 'draft' where id = $1`, [postId])
    }))
    expect(error.message).toMatch(/already been published/i)
  })

  test('cannot be deleted, because that would cascade away the receipt', async () => {
    const postId = await makePost('published')

    const error = await expectRejected(() => asUser(url, ALICE, 'aal2', async (q) => {
      await q(`delete from public.posts where id = $1`, [postId])
    }))
    expect(error.message).toMatch(/lose the record/i)
  })

  test('the refusal holds against the admin client too, not just a signed-in user', async () => {
    // The worker runs as service_role. It has no reason to rewrite a published
    // post either, and a control that only stops the browser is not a control.
    const postId = await makePost('published')

    const error = await expectRejected(() => asAdmin(url, async (q) => {
      await q(`update public.posts set body = '{"text":"by the worker"}'::jsonb where id = $1`,
        [postId])
    }))
    expect(error.message).toMatch(/already been published/i)
  })

  test('re-saving it unchanged is not an error, so an idempotent write still works', async () => {
    const postId = await makePost('published')

    await asAdmin(url, async (q) => {
      await q(`update public.posts set body = body where id = $1`, [postId])
    })

    const body = await asAdmin(url, async (q) =>
      (await q(`select body from public.posts where id = $1`, [postId])).rows[0].body)
    expect(body).toEqual({ text: 'hello' })
  })

  test('one published row is enough, even when its siblings are not', async () => {
    // A post going to two accounts has two scheduled rows. If one went out, the
    // post is published as far as the world is concerned.
    const postId = await makePost('published')
    await asAdmin(url, async (q) => {
      await q(
        `insert into public.scheduled_posts
           (post_id, social_account_id, business_id, scheduled_for, status)
         values ($1,$2,$3, now(), 'scheduled')`,
        [postId, accountId, businessA])
    })

    const error = await expectRejected(() => asUser(url, ALICE, 'aal2', async (q) => {
      await q(`update public.posts set body = '{"text":"half out"}'::jsonb where id = $1`, [postId])
    }))
    expect(error.message).toMatch(/already been published/i)
  })
})

describe('the helper the trigger asks', () => {
  test('is not callable by a signed-in user, like every other function in app', async () => {
    const postId = await makeDraft()

    const error = await expectRejected(() => asUser(url, ALICE, 'aal2', async (q) => {
      await q(`select app.post_has_been_published($1)`, [postId])
    }))
    expect(error.message).toMatch(/permission denied/i)
  })
})
