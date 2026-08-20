/**
 * Regression tests for the findings of the Phase 1 security review.
 *
 * Every test in this file corresponds to a specific hole that existed in an
 * earlier revision and was proven exploitable against a real database. They are
 * kept together so it is obvious what they are for: if one of these ever fails,
 * a known vulnerability has come back.
 */
import { beforeAll, afterAll, describe, expect, test } from 'vitest'
import { asAdmin, asAnon, asUser, dropDatabase, expectRejected, freshDatabase } from './helpers'

const DB = 'postdeck_hardening_test'
let url: string

const OWNER = '11111111-1111-1111-1111-111111111111'
const VIEWER = '33333333-3333-3333-3333-333333333333'
const OUTSIDER = '22222222-2222-2222-2222-222222222222'

let businessA: string
let businessB: string
let accountA: string
let accountB: string
const ALICE_TOKEN = 'ALICE-REAL-OAUTH-TOKEN-do-not-leak'
const PROVIDER_KEY = 'META_APP_SECRET_platform_wide'

beforeAll(async () => {
  url = await freshDatabase(DB)
  await asAdmin(url, async (q) => {
    await q(`insert into auth.users (id, email) values
      ($1,'owner@example.com'), ($2,'viewer@example.com'), ($3,'outsider@example.com')`,
      [OWNER, VIEWER, OUTSIDER])

    businessA = (await q(`insert into public.businesses (name) values ('Tenant A') returning id`)).rows[0].id
    businessB = (await q(`insert into public.businesses (name) values ('Tenant B') returning id`)).rows[0].id

    await q(`insert into public.business_members (business_id, user_id, role) values ($1,$2,'owner')`, [businessA, OWNER])
    await q(`insert into public.business_members (business_id, user_id, role) values ($1,$2,'viewer')`, [businessA, VIEWER])
    await q(`insert into public.business_members (business_id, user_id, role) values ($1,$2,'owner')`, [businessB, OUTSIDER])

    accountA = (await q(`insert into public.social_accounts (business_id, platform, label) values ($1,'facebook','A page') returning id`, [businessA])).rows[0].id
    accountB = (await q(`insert into public.social_accounts (business_id, platform, label) values ($1,'facebook','B page') returning id`, [businessB])).rows[0].id

    await q(`insert into public.posts (business_id, created_by, body) values ($1,$2,'{"text":"tenant A"}')`, [businessA, OWNER])

    // Alice's real credential, and a platform-wide provider key, both in the Vault.
    await q(`select app.store_account_credential($1,$2)`, [accountA, ALICE_TOKEN])
    await q(`select vault.create_secret($1,'meta_app_secret','platform key')`, [PROVIDER_KEY])
  })
}, 60_000)

afterAll(async () => { await dropDatabase(DB) })

// ---------------------------------------------------------------------------
describe('C1 — a tenant cannot retarget their credential pointer at someone else\'s secret', () => {
  test('encrypted_credential_ref is not writable by a signed-in user at all', async () => {
    await asUser(url, OUTSIDER, 'aal2', async (q) => {
      const err = await expectRejected(() =>
        q(`update public.social_accounts set encrypted_credential_ref = $1 where id = $2`,
          ['social_account_' + accountA.replace(/-/g, ''), accountB]))
      expect(err.message).toMatch(/permission denied/i)
    })
  })

  test('nor can it be pointed at a platform-wide provider key', async () => {
    await asUser(url, OUTSIDER, 'aal2', async (q) => {
      const err = await expectRejected(() =>
        q(`update public.social_accounts set encrypted_credential_ref = 'meta_app_secret' where id = $1`, [accountB]))
      expect(err.message).toMatch(/permission denied/i)
    })
  })

  test('the columns a user IS allowed to edit still work', async () => {
    await asUser(url, OUTSIDER, 'aal2', async (q) => {
      const r = await q(`update public.social_accounts set label='renamed' where id=$1 returning label`, [accountB])
      expect(r.rows[0].label).toBe('renamed')
    })
  })

  test('reading a credential takes an account id, so the stored reference is never a lookup key', async () => {
    await asAdmin(url, async (q) => {
      // The account id is the only input. Even if the ref column were tampered
      // with, the secret name is derived, so the wrong secret cannot be fetched.
      expect((await q(`select app.read_account_credential($1) as v`, [accountA])).rows[0].v).toBe(ALICE_TOKEN)
      expect((await q(`select app.read_account_credential($1) as v`, [accountB])).rows[0].v).toBeNull()
    })
  })

  test('an unknown account id is refused rather than silently returning some other secret', async () => {
    await asAdmin(url, async (q) => {
      const err = await expectRejected(() =>
        q(`select app.read_account_credential('00000000-0000-0000-0000-000000000000')`))
      expect(err.message).toMatch(/no such social account/i)
    })
  })
})

// ---------------------------------------------------------------------------
describe('C3 — a signed-out visitor holds no privilege on anything', () => {
  test.each(['businesses', 'business_members', 'social_accounts', 'posts', 'scheduled_posts', 'audit_log'])(
    'anon cannot TRUNCATE %s (RLS does not filter TRUNCATE and it fires no row triggers)',
    async (table) => {
      await asAnon(url, async (q) => {
        const err = await expectRejected(() => q(`truncate public.${table} cascade`))
        expect(err.message).toMatch(/permission denied|must be owner/i)
      })
    })

  test.each(['businesses', 'posts', 'audit_log'])('anon cannot select from %s', async (table) => {
    await asAnon(url, async (q) => {
      const err = await expectRejected(() => q(`select * from public.${table}`))
      expect(err.message).toMatch(/permission denied/i)
    })
  })

  test('anon holds no ACL entry whatsoever on any table', async () => {
    await asAdmin(url, async (q) => {
      const r = await q(`
        select relname, relacl::text from pg_class c join pg_namespace n on n.oid = c.relnamespace
        where n.nspname='public' and c.relkind='r'`)
      for (const row of r.rows) {
        expect(row.relacl ?? '', `${row.relname} grants something to anon`).not.toMatch(/(^|,)anon=/)
      }
    })
  })

  test('even a signed-in user cannot TRUNCATE, so the audit log cannot be wiped', async () => {
    await asUser(url, OWNER, 'aal2', async (q) => {
      const err = await expectRejected(() => q(`truncate public.audit_log cascade`))
      expect(err.message).toMatch(/permission denied|must be owner/i)
    })
  })
})

// ---------------------------------------------------------------------------
describe('H1 — the role column actually restricts what a member may do', () => {
  test('a viewer can read their business', async () => {
    await asUser(url, VIEWER, 'aal2', async (q) => {
      expect((await q(`select * from public.posts`)).rowCount).toBeGreaterThan(0)
    })
  })

  test('a viewer cannot delete posts', async () => {
    await asUser(url, VIEWER, 'aal2', async (q) => {
      expect((await q(`delete from public.posts where business_id=$1`, [businessA])).rowCount).toBe(0)
    })
    await asAdmin(url, async (q) => {
      expect((await q(`select count(*)::int n from public.posts where business_id=$1`, [businessA])).rows[0].n).toBeGreaterThan(0)
    })
  })

  test('a viewer cannot create a post', async () => {
    await asUser(url, VIEWER, 'aal2', async (q) => {
      const err = await expectRejected(() =>
        q(`insert into public.posts (business_id, created_by, body) values ($1,$2,'{}')`, [businessA, VIEWER]))
      expect(err.message).toMatch(/row-level security/i)
    })
  })

  test('a viewer cannot disconnect a social account', async () => {
    await asUser(url, VIEWER, 'aal2', async (q) => {
      expect((await q(`delete from public.social_accounts where id=$1`, [accountA])).rowCount).toBe(0)
    })
  })

  test('an owner still can do all of those', async () => {
    await asUser(url, OWNER, 'aal2', async (q) => {
      const r = await q(`insert into public.posts (business_id, created_by, body) values ($1,$2,'{}') returning id`, [businessA, OWNER])
      expect(r.rowCount).toBe(1)
      expect((await q(`delete from public.posts where id=$1`, [r.rows[0].id])).rowCount).toBe(1)
    })
  })
})

// ---------------------------------------------------------------------------
describe('H3 — a post cannot be stamped with somebody else\'s authorship', () => {
  test('you cannot create a post attributed to another user', async () => {
    await asUser(url, OWNER, 'aal2', async (q) => {
      const err = await expectRejected(() =>
        q(`insert into public.posts (business_id, created_by, body) values ($1,$2,'{}')`, [businessA, OUTSIDER]))
      expect(err.message).toMatch(/row-level security/i)
    })
  })

  test('the foreign key can no longer be used to ask whether a user id exists', async () => {
    // Both a real id and a random one must fail the SAME way -- via the policy,
    // before the foreign key is ever consulted -- so the error reveals nothing.
    await asUser(url, OWNER, 'aal2', async (q) => {
      // Savepoints: a rejected statement poisons the surrounding transaction, and
      // without these the second attempt would report "transaction aborted"
      // instead of its own real error.
      await q(`savepoint s`)
      const real = await expectRejected(() =>
        q(`insert into public.posts (business_id, created_by, body) values ($1,$2,'{}')`, [businessA, OUTSIDER]))
      await q(`rollback to savepoint s`)
      const fake = await expectRejected(() =>
        q(`insert into public.posts (business_id, created_by, body) values ($1,'99999999-9999-9999-9999-999999999999','{}')`, [businessA]))
      await q(`rollback to savepoint s`)
      expect(real.message).toMatch(/row-level security/i)
      expect(fake.message).toMatch(/row-level security/i)
      expect(fake.message).not.toMatch(/foreign key|not present in table/i)
    })
  })
})

// ---------------------------------------------------------------------------
describe('M1 — the audit log id sequence cannot be tampered with', () => {
  test('a signed-in user cannot burn ids to fake gaps in the audit trail', async () => {
    await asUser(url, OWNER, 'aal2', async (q) => {
      const err = await expectRejected(() => q(`select nextval('public.audit_log_id_seq')`))
      expect(err.message).toMatch(/permission denied/i)
    })
  })

  test('nor can a signed-out visitor', async () => {
    await asAnon(url, async (q) => {
      const err = await expectRejected(() => q(`select setval('public.audit_log_id_seq', 1)`))
      expect(err.message).toMatch(/permission denied/i)
    })
  })
})

// ---------------------------------------------------------------------------
describe('M2 — a cascade delete still produces an attributable audit row', () => {
  test('deleting a post files the child scheduled_posts delete against the right business', async () => {
    let postId: string
    await asAdmin(url, async (q) => {
      postId = (await q(`insert into public.posts (business_id, created_by, body) values ($1,$2,'{}') returning id`, [businessA, OWNER])).rows[0].id
      await q(`insert into public.scheduled_posts (post_id, social_account_id, business_id, scheduled_for)
               values ($1,$2,$3, now())`, [postId, accountA, businessA])
    })

    const before = await asAdmin(url, async (q) => (await q(`select coalesce(max(id),0) m from public.audit_log`)).rows[0].m)
    await asUser(url, OWNER, 'aal2', async (q) => { await q(`delete from public.posts where id=$1`, [postId]) })

    const rows = await asAdmin(url, async (q) =>
      (await q(`select * from public.audit_log where id > $1 order by id`, [before])).rows)

    const cascade = rows.find((r) => r.action === 'scheduled_posts.delete')
    expect(cascade, 'the cascade delete must be audited').toBeTruthy()
    // The whole point: it must be attributed, or no tenant can ever see it.
    expect(cascade.business_id).toBe(businessA)

    // And the owner must actually be able to read it back.
    await asUser(url, OWNER, 'aal2', async (q) => {
      const visible = await q(`select * from public.audit_log where id = $1`, [cascade.id])
      expect(visible.rowCount).toBe(1)
    })
  })
})

// ---------------------------------------------------------------------------
// CLASS TESTS
//
// The tests above pin specific findings. These hunt the whole class each finding
// belonged to, so the next instance is caught without anyone having to think of it.
// ---------------------------------------------------------------------------

describe('CLASS: no function in schema app is executable by PUBLIC', () => {
  test('every app function has an explicit ACL', async () => {
    // A SECURITY DEFINER function left PUBLIC-executable is an RLS bypass handed to
    // anyone with a SQL channel. One such function was missed by hand; this checks
    // all of them, including any a future migration adds.
    await asAdmin(url, async (q) => {
      const r = await q(`
        select proname, proacl::text as acl, prosecdef
        from pg_proc p join pg_namespace n on n.oid = p.pronamespace
        where n.nspname = 'app' order by proname`)
      expect(r.rowCount).toBeGreaterThan(0)
      for (const fn of r.rows) {
        expect(fn.acl, `app.${fn.proname} is executable by PUBLIC`).not.toBeNull()
      }
    })
  })

  test('a signed-in user cannot forge audit rows via the trigger function', async () => {
    // The concrete attack: attach app.audit_row_change to a table you control and
    // it writes into whatever business_id your row claims, as the function owner.
    await asUser(url, OUTSIDER, 'aal2', async (q) => {
      await q(`create temp table forge (id uuid, business_id uuid)`)
      const err = await expectRejected(() =>
        q(`create trigger t after insert on forge for each row execute function app.audit_row_change()`))
      expect(err.message).toMatch(/permission denied/i)
    })
  })
})

describe('CLASS: anon is granted nothing, now and for future migrations', () => {
  test('a table created by a later migration is not granted to anon', async () => {
    // Supabase's default privileges grant ALL on new public tables to anon. A
    // one-time revoke fixes today's tables; the next migration reopens the hole
    // unless the default privilege itself is cancelled.
    await asAdmin(url, async (q) => {
      await q(`create table public.future_phase_table (id int)`)
      try {
        const r = await q(`
          select has_table_privilege('anon','public.future_phase_table','SELECT')   as sel,
                 has_table_privilege('anon','public.future_phase_table','TRUNCATE') as trunc,
                 has_table_privilege('anon','public.future_phase_table','DELETE')   as del`)
        expect(r.rows[0].sel,   'anon can SELECT a new table').toBe(false)
        expect(r.rows[0].trunc, 'anon can TRUNCATE a new table').toBe(false)
        expect(r.rows[0].del,   'anon can DELETE from a new table').toBe(false)
      } finally {
        await q(`drop table public.future_phase_table`)
      }
    })
  })
})

describe('CLASS: the credential reference is unwritable through every path', () => {
  test('not on UPDATE and not on INSERT either', async () => {
    // The first fix removed it from the UPDATE grant and left INSERT table-wide,
    // so a brand-new row could still be pointed at another tenant's secret.
    await asAdmin(url, async (q) => {
      const r = await q(`
        select has_column_privilege('authenticated','public.social_accounts','encrypted_credential_ref','INSERT') as ins,
               has_column_privilege('authenticated','public.social_accounts','encrypted_credential_ref','UPDATE') as upd`)
      expect(r.rows[0].ins, 'encrypted_credential_ref is insertable').toBe(false)
      expect(r.rows[0].upd, 'encrypted_credential_ref is updatable').toBe(false)
    })
  })

  test('inserting a row that names another tenant\'s secret is refused', async () => {
    await asUser(url, OUTSIDER, 'aal2', async (q) => {
      const err = await expectRejected(() =>
        q(`insert into public.social_accounts (business_id, platform, label, encrypted_credential_ref)
           values ($1,'instagram','Stolen',$2)`,
          [businessB, 'social_account_' + accountA.replace(/-/g, '')]))
      expect(err.message).toMatch(/permission denied/i)
    })
  })

  test('nor one naming the platform-wide provider key', async () => {
    await asUser(url, OUTSIDER, 'aal2', async (q) => {
      const err = await expectRejected(() =>
        q(`insert into public.social_accounts (business_id, platform, label, encrypted_credential_ref)
           values ($1,'instagram','Stolen','meta_app_secret')`, [businessB]))
      expect(err.message).toMatch(/permission denied/i)
    })
  })
})

describe('CLASS: every helper granted to authenticated refuses an aal1 session', () => {
  test.each([
    ['is_member_of',        `select app.is_member_of($1) as v`],
    ['has_role_in',         `select app.has_role_in($1, array['owner']::public.member_role[]) as v`],
  ])('%s answers false without TOTP, even for a genuine member', async (_name, sql) => {
    // The RESTRICTIVE MFA policy guards tables. These functions are reachable
    // independently of any table, so each carries the check itself.
    await asUser(url, OWNER, 'aal1', async (q) => {
      expect((await q(sql, [businessA])).rows[0].v).toBe(false)
    })
    await asUser(url, OWNER, 'aal2', async (q) => {
      expect((await q(sql, [businessA])).rows[0].v).toBe(true)
    })
  })

  test('post_belongs_to and account_belongs_to do not confirm other tenants\' relationships', async () => {
    // Taking the business id as an argument turned a lookup oracle into a
    // confirmation oracle. Scoping to the caller's memberships removes it.
    await asUser(url, OUTSIDER, 'aal2', async (q) => {
      expect((await q(`select app.account_belongs_to($1,$2) as v`, [accountA, businessA])).rows[0].v).toBe(false)
    })
    await asUser(url, OWNER, 'aal1', async (q) => {
      expect((await q(`select app.account_belongs_to($1,$2) as v`, [accountA, businessA])).rows[0].v).toBe(false)
    })
    await asUser(url, OWNER, 'aal2', async (q) => {
      expect((await q(`select app.account_belongs_to($1,$2) as v`, [accountA, businessA])).rows[0].v).toBe(true)
    })
  })
})

describe('the Vault write path is audited, including a rotation', () => {
  test('storing and rotating a credential each write a meaningful audit row', async () => {
    const before = await asAdmin(url, async (q) => (await q(`select coalesce(max(id),0) m from public.audit_log`)).rows[0].m)
    await asAdmin(url, async (q) => {
      await q(`select app.store_account_credential($1,'ROTATED-TOKEN-V2')`, [accountA])
    })
    const rows = await asAdmin(url, async (q) =>
      (await q(`select * from public.audit_log where id > $1 order by id`, [before])).rows)

    const credentialRow = rows.find((r) => String(r.action).startsWith('social_account.credential.'))
    expect(credentialRow, 'a credential write must be audited').toBeTruthy()
    expect(credentialRow.action).toBe('social_account.credential.rotated')
    expect(credentialRow.business_id).toBe(businessA)
    // And it must never contain the credential itself.
    expect(JSON.stringify(credentialRow)).not.toContain('ROTATED-TOKEN-V2')
  })

  test('storing against an unknown account is refused rather than silently unaudited', async () => {
    await asAdmin(url, async (q) => {
      const err = await expectRejected(() =>
        q(`select app.store_account_credential('99999999-9999-9999-9999-999999999999','SECRET')`))
      expect(err.message).toMatch(/no such social account/i)
    })
  })
})

test('authorship cannot be erased', async () => {
  await asUser(url, OWNER, 'aal2', async (q) => {
    const id = (await q(`insert into public.posts (business_id, created_by, body) values ($1,$2,'{}') returning id`,
      [businessA, OWNER])).rows[0].id
    const err = await expectRejected(() =>
      q(`update public.posts set created_by = null where id = $1`, [id]))
    expect(err.message).toMatch(/row-level security/i)
  })
})
