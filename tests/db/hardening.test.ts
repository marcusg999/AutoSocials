/**
 * Regression tests for the findings of the Phase 1 security review.
 *
 * Every test in this file corresponds to a specific hole that existed in an
 * earlier revision and was proven exploitable against a real database. They are
 * kept together so it is obvious what they are for: if one of these ever fails,
 * a known vulnerability has come back.
 */
import { beforeAll, afterAll, describe, expect, test } from 'vitest'
import { asAdmin, asAnon, asUser, dropDatabase, expectRejected, freshDatabase, shimOnlyDatabase } from './helpers'

/**
 * Every schema this project is responsible for.
 *
 * Written as an exclusion, not a list. Naming the schemas to scan means a table in
 * a schema nobody thought of is invisible -- verified: a business-scoped table in a
 * `reporting` schema was fully cross-tenant readable while every class test stayed
 * green. The excluded set is Postgres's own catalogs plus the schemas Supabase owns
 * and we do not control.
 */
const OUR_SCHEMAS = `
  n.nspname not in ('pg_catalog', 'information_schema', 'pg_toast',
                    'auth', 'storage', 'realtime', 'vault',
                    'graphql', 'graphql_public', 'supabase_functions', 'cron', 'net')
  and n.nspname not like 'pg_temp%' and n.nspname not like 'pg_toast_temp%'
`

/**
 * Functions we did not write are exempt from the function checks -- but the test is
 * "does this function belong to an EXTENSION", not "is it in a particular schema".
 * Exempting a whole schema would also exempt anything of ours that lands there, and
 * `extensions` is deliberately IN OUR_SCHEMAS above because 0010 grants
 * `authenticated` USAGE on it: a business-scoped table created there was
 * cross-tenant readable while every class test stayed green.
 */
const NOT_OUR_FUNCTIONS = `
  not exists (
    select 1 from pg_depend d
    where d.objid = p.oid and d.deptype = 'e'
  )
`

/** Every privilege that lets a role get data in or out of a relation. */
const ANY_DATA_PRIVILEGE = ['SELECT', 'INSERT', 'UPDATE', 'DELETE'] as const

const DB = 'postdeck_hardening_test'
let url: string

const OWNER = '11111111-1111-1111-1111-111111111111'
const VIEWER = '33333333-3333-3333-3333-333333333333'
const OUTSIDER = '22222222-2222-2222-2222-222222222222'
const MANAGER = '55555555-5555-5555-5555-555555555555'

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
      ($1,'owner@example.com'), ($2,'viewer@example.com'), ($3,'outsider@example.com'),
      ($4,'manager@example.com')`,
      [OWNER, VIEWER, OUTSIDER, MANAGER])

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
  test('PUBLIC cannot execute any of them', async () => {
    // Ask Postgres the actual question. An earlier version asserted
    // `proacl is not null`, which is a PROXY for the property and not the property:
    // the moment any grant is issued Postgres materialises the ACL *including* the
    // default PUBLIC entry, so a function that was both PUBLIC-executable and
    // explicitly granted passed. has_function_privilege cannot be fooled that way.
    await asAdmin(url, async (q) => {
      const r = await q(`
        select p.proname,
               has_function_privilege('public', p.oid, 'EXECUTE') as public_can_execute
        from pg_proc p join pg_namespace n on n.oid = p.pronamespace
        where n.nspname = 'app' order by p.proname`)
      expect(r.rowCount).toBeGreaterThan(0)
      for (const fn of r.rows) {
        expect(fn.public_can_execute, `app.${fn.proname} is executable by PUBLIC`).toBe(false)
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
  test('a FUNCTION created by a later migration is not executable by PUBLIC', async () => {
    // The table half of this was fixed first and the function half was missed.
    // Functions default to PUBLIC EXECUTE, and `authenticated` holds usage on both
    // schemas, so a new SECURITY DEFINER helper is reachable by anyone until the
    // default privilege itself is cancelled.
    await asAdmin(url, async (q) => {
      await q(`create function app.future_helper() returns text
               language sql security definer set search_path='' as $$ select 'ran' $$`)
      await q(`create function public.future_public_helper() returns text
               language sql security definer set search_path='' as $$ select 'ran' $$`)
      try {
        const r = await q(`
          select has_function_privilege('public','app.future_helper()','EXECUTE')            as app_fn,
                 has_function_privilege('public','public.future_public_helper()','EXECUTE')   as public_fn`)
        expect(r.rows[0].app_fn,    'a new app function is PUBLIC-executable').toBe(false)
        expect(r.rows[0].public_fn, 'a new public function is PUBLIC-executable').toBe(false)
      } finally {
        await q(`drop function app.future_helper()`)
        await q(`drop function public.future_public_helper()`)
      }
    })
  })

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

describe('authorship is set once and never changes', () => {
  test('created_by is not in the UPDATE grant at all', async () => {
    await asAdmin(url, async (q) => {
      const r = await q(`
        select has_column_privilege('authenticated','public.posts','created_by','UPDATE') as upd,
               has_column_privilege('authenticated','public.posts','business_id','UPDATE') as biz`)
      expect(r.rows[0].upd, 'created_by is editable').toBe(false)
      expect(r.rows[0].biz, 'business_id is editable, so a post could be moved between tenants').toBe(false)
    })
  })

  test('a trigger pins it even for a caller that bypasses the grant', async () => {
    // Belt and braces: the grant stops the app, the trigger stops a worker or a
    // migration running as the owner.
    let id: string
    await asAdmin(url, async (q) => {
      id = (await q(`insert into public.posts (business_id, created_by, body) values ($1,$2,'{}') returning id`,
        [businessA, OWNER])).rows[0].id
      await q(`update public.posts set created_by = null where id = $1`, [id])
      const after = await q(`select created_by from public.posts where id = $1`, [id])
      expect(after.rows[0].created_by, 'authorship was erased').toBe(OWNER)
    })
  })

  test('a manager can edit a colleague\'s post without stealing authorship', async () => {
    // The regression: requiring created_by = auth.uid() on the NEW row made
    // collaborative editing impossible and left reassignment as the only way through.
    let id: string
    await asAdmin(url, async (q) => {
      id = (await q(`insert into public.posts (business_id, created_by, body) values ($1,$2,'{}') returning id`,
        [businessA, OWNER])).rows[0].id
      await q(`insert into public.business_members (business_id, user_id, role) values ($1,$2,'manager')
               on conflict do nothing`, [businessA, MANAGER])
    })
    await asUser(url, MANAGER, 'aal2', async (q) => {
      const r = await q(`update public.posts set status='approved' where id=$1 returning created_by`, [id])
      expect(r.rowCount, 'a manager could not edit a colleague\'s post').toBe(1)
      expect(r.rows[0].created_by, 'authorship changed hands').toBe(OWNER)
    })
  })
})

// ---------------------------------------------------------------------------

describe('CLASS: only the intended roles can execute anything', () => {
  // The five yes/no helpers an RLS policy needs a signed-in user to be able to call.
  // Everything else we write, in any schema, is server-side only.
  const CALLABLE_BY_AUTHENTICATED = new Set([
    'app.has_completed_mfa', 'app.is_member_of', 'app.has_role_in',
    'app.post_belongs_to', 'app.account_belongs_to',
  ])

  test('no function we wrote is callable by anon, and only the allowlist by authenticated', async () => {
    // Checked across EVERY schema we own and for all three roles.
    //
    // An earlier version checked all three roles inside schema `app` but only
    // `anon` outside it -- and `public` is exactly what PostgREST exposes as
    // /rest/v1/rpc/<name>, while `authenticated`, not `anon`, is the tenancy threat
    // model. Verified: a SECURITY DEFINER function in `public` granted to
    // `authenticated` returned every tenant's posts while the suite stayed green.
    await asAdmin(url, async (q) => {
      const r = await q(`
        select n.nspname || '.' || p.proname as name,
               has_function_privilege('anon',          p.oid, 'EXECUTE') as anon_exec,
               has_function_privilege('authenticated', p.oid, 'EXECUTE') as auth_exec,
               has_function_privilege('public',        p.oid, 'EXECUTE') as public_exec
        from pg_proc p join pg_namespace n on n.oid = p.pronamespace
        where ${OUR_SCHEMAS} and ${NOT_OUR_FUNCTIONS}
        order by 1`)

      expect(r.rowCount, 'no functions found — this test would be vacuous').toBeGreaterThan(0)
      for (const fn of r.rows) {
        expect(fn.anon_exec,   `${fn.name} is callable by anon`).toBe(false)
        expect(fn.public_exec, `${fn.name} is callable by PUBLIC`).toBe(false)
        expect(
          fn.auth_exec,
          `${fn.name} is callable by authenticated but is not on the allowlist`,
        ).toBe(CALLABLE_BY_AUTHENTICATED.has(fn.name))
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

describe('CLASS: every business-scoped table is audited', () => {
  test('any table carrying a business_id has the audit trigger', async () => {
    // The audited-table list in 0007 is written by hand, so a table added by a later
    // phase would be silently unaudited and quality bar 4 would quietly stop being
    // true. This derives the expected set from the schema.
    //
    // Business scope is detected by FOREIGN KEY to businesses(id), not by a column
    // named `business_id`, and across every schema rather than just `public`. Both
    // narrowings were real holes: a table in schema `app`, or one whose column is
    // called `tenant_id`, was cross-tenant readable with no audit rows while this
    // test stayed green.
    await asAdmin(url, async (q) => {
      const r = await q(`
        select n.nspname || '.' || c.relname as table_name,
               exists (
                 select 1 from pg_trigger t
                 where t.tgrelid = c.oid and not t.tgisinternal and t.tgname = 'audit_changes'
               ) as has_audit_trigger
        from pg_class c
        join pg_namespace n on n.oid = c.relnamespace
        where ${OUR_SCHEMAS} and c.relkind in ('r', 'p')
          -- audit_log references businesses but must never be audited: a trigger
          -- writing an audit row for every audit row does not terminate.
          and not (n.nspname = 'public' and c.relname = 'audit_log')
          and (
            (n.nspname = 'public' and c.relname = 'businesses')
            or exists (
              select 1 from pg_constraint fk
              where fk.conrelid = c.oid and fk.contype = 'f'
                and fk.confrelid = 'public.businesses'::regclass
            )
          )
        order by 1`)

      expect(r.rowCount, 'no business-scoped tables found — this test would be vacuous')
        .toBeGreaterThan(0)
      for (const table of r.rows) {
        expect(table.has_audit_trigger, `${table.table_name} is not audited`).toBe(true)
      }
    })
  })
})

describe('CLASS: every table is behind row level security', () => {
  test('no table anywhere is left without RLS enabled and forced', async () => {
    // Asserted by exclusion rather than by listing. A hardcoded list of the six
    // tables that exist today cannot notice a seventh, and a new table without RLS
    // is readable by every tenant from the moment it is created.
    await asAdmin(url, async (q) => {
      const r = await q(`
        select n.nspname || '.' || c.relname as table_name,
               c.relrowsecurity, c.relforcerowsecurity
        from pg_class c join pg_namespace n on n.oid = c.relnamespace
        where ${OUR_SCHEMAS} and c.relkind in ('r', 'p', 'f')
          -- The migration ledger holds no tenant data and is written before any
          -- policy could exist.
          and not (n.nspname = 'public' and c.relname = 'schema_migrations')
        order by 1`)

      expect(r.rowCount, 'no tables found — this test would be vacuous').toBeGreaterThan(0)
      for (const table of r.rows) {
        expect(table.relrowsecurity, `${table.table_name} has no row level security`).toBe(true)
        expect(table.relforcerowsecurity, `${table.table_name} does not FORCE row level security`).toBe(true)
      }
    })
  })
})

describe('CLASS: a view cannot be used to read or write around row level security', () => {
  test('every view a client role can touch runs as the caller, and no materialized or foreign table is reachable', async () => {
    // Views are the gap RLS does not cover. A view executes with the privileges of
    // its OWNER unless `security_invoker = true`, which is off by default -- so a
    // view over posts hands every tenant every row with all the policies intact.
    //
    // The check covers INSERT, UPDATE and DELETE as well as SELECT. An earlier
    // version tested SELECT only, so a view granted INSERT-but-not-SELECT fell
    // through the loop with no assertions at all. Verified: a cross-tenant INSERT
    // through exactly such a view landed a forged row in another tenant's posts,
    // while the direct insert was correctly refused by RLS.
    //
    // Materialized and foreign tables cannot respect RLS at all -- one stores its
    // own copy, the other lives in another database -- so they must not be
    // reachable by a client role under any conditions.
    await asAdmin(url, async (q) => {
      const r = await q(`
        select n.nspname || '.' || c.relname            as name,
               c.relkind::text                          as kind,
               coalesce(array_to_string(c.reloptions, ','), '') as options,
               ${ANY_DATA_PRIVILEGE.map((p) => {
                 // DELETE has no column-level form; the other three do, and
                 // has_table_privilege returns FALSE for a column-only grant.
                 // Missing that let a view granted `insert (col, col)` -- with no
                 // table-level INSERT at all -- pass every assertion here while
                 // accepting a cross-tenant write.
                 const fn = p === 'DELETE' ? 'has_table_privilege' : 'has_any_column_privilege'
                 return `
                 ${fn}('anon',          c.oid, '${p}') as anon_${p.toLowerCase()},
                 ${fn}('authenticated', c.oid, '${p}') as auth_${p.toLowerCase()}`
               }).join(',')}
        from pg_class c join pg_namespace n on n.oid = c.relnamespace
        where ${OUR_SCHEMAS} and c.relkind in ('v', 'm', 'f')
        order by 1`)

      for (const rel of r.rows) {
        const anonReach = ANY_DATA_PRIVILEGE.filter((p) => rel[`anon_${p.toLowerCase()}`])
        const authReach = ANY_DATA_PRIVILEGE.filter((p) => rel[`auth_${p.toLowerCase()}`])

        expect(anonReach, `${rel.name} is reachable by anon via ${anonReach.join(', ')}`).toEqual([])

        if (rel.kind === 'm' || rel.kind === 'f') {
          const kind = rel.kind === 'm' ? 'materialized view' : 'foreign table'
          expect(authReach, `${rel.name} is a ${kind} reachable by authenticated via `
            + `${authReach.join(', ')}; it cannot respect row level security`).toEqual([])
          continue
        }

        if (authReach.length > 0) {
          expect(rel.options, `${rel.name} is reachable by authenticated via `
            + `${authReach.join(', ')} but does not set security_invoker=true, so it runs as its `
            + 'owner and bypasses every policy beneath it')
            .toMatch(/security_invoker\s*=\s*(true|on)/i)
        }
      }
    })
  })
})

describe('CLASS: the enumeration each check performs is the complete one', () => {
  // The lesson of six review rounds. Every class test here models the database with
  // a filter, and each time a filter has been narrower than the property it claims
  // -- one schema, one relkind, one privilege, one column name. These assertions
  // exist so the NEXT narrowing fails loudly instead of being discovered by a
  // reviewer walking a row across a tenant boundary.

  test('no relation kind we own escapes both the table checks and the view checks', async () => {
    await asAdmin(url, async (q) => {
      const r = await q(`
        select distinct c.relkind::text as kind
        from pg_class c join pg_namespace n on n.oid = c.relnamespace
        where ${OUR_SCHEMAS} and c.relkind not in ('i', 'S', 'c', 't', 'I')
        order by 1`)
      const covered = ['r', 'p', 'f', 'v', 'm']
      for (const row of r.rows) {
        expect(covered, `relkind '${row.kind}' exists in a schema we own but no class test looks at it`)
          .toContain(row.kind)
      }
    })
  })

  test('every schema we own is actually scanned, so a new one cannot hide a table', async () => {
    await asAdmin(url, async (q) => {
      const all = await q(`select nspname from pg_namespace n where ${OUR_SCHEMAS} order by 1`)
      const names = all.rows.map((x) => x.nspname)
      // The schemas this project creates. A schema appearing here that nobody
      // expected is fine -- it is scanned. One MISSING would mean the exclusion
      // list had grown to swallow something of ours.
      expect(names, 'the public schema is not being scanned').toContain('public')
      expect(names, 'the app schema is not being scanned').toContain('app')
    })
  })

  test('our migrations create nothing in a schema the class tests do not scan', async () => {
    // The assertion above can only notice a schema of ours going MISSING from the
    // scanned set. It cannot notice one of our objects landing in an EXCLUDED one --
    // and `storage`, `auth` and `realtime` all exist on a real Supabase project,
    // with `authenticated` already holding USAGE. A migration creating a
    // business-scoped table and a non-security_invoker view over public.posts in
    // `storage` gave a live cross-tenant read and write with the suite at 275/275.
    //
    // So the scanned set is no longer a claim: everything our migrations add is
    // diffed against a database that has the Supabase shim and nothing else, and
    // every new object must land somewhere the checks above actually look.
    // Each object's ACL and owner, not just its name.
    //
    // Diffing the SET OF OBJECTS can only ever notice something being CREATED. It
    // is blind to a migration that modifies an object the baseline already has --
    // and `grant select on auth.users to authenticated`, two lines in a migration,
    // handed every user's email address to every signed-in member of every tenant
    // while this diff stayed empty and `auth` was excluded from every other check.
    // Verified: 109/109 green with that grant applied.
    //
    // So the signature includes the grants and the owner. A `GRANT`, a `REVOKE`, an
    // `ALTER ... OWNER TO` or a `SET ROLE` that changes one now changes the
    // signature, and the diff sees it.
    const INVENTORY = `
      select 'schema ' || n.nspname || ' acl=' || coalesce(n.nspacl::text, '') as name
      from pg_namespace n
      where n.nspname not like 'pg_%' and n.nspname <> 'information_schema'
      union all
      select n.nspname || '.' || c.relname
             || ' acl=' || coalesce(c.relacl::text, '')
             || ' owner=' || pg_get_userbyid(c.relowner) as name
      from pg_class c join pg_namespace n on n.oid = c.relnamespace
      where c.relkind in ('r','p','v','m','f') and n.nspname not like 'pg_%'
        and n.nspname <> 'information_schema'
      union all
      select n.nspname || '.' || p.proname || '()'
             || ' acl=' || coalesce(p.proacl::text, '')
             || ' owner=' || pg_get_userbyid(p.proowner) as name
      from pg_proc p join pg_namespace n on n.oid = p.pronamespace
      where n.nspname not like 'pg_%' and n.nspname <> 'information_schema'
      union all
      -- Column-level grants live in pg_attribute, not in relacl.
      select n.nspname || '.' || c.relname || '.' || a.attname
             || ' acl=' || coalesce(a.attacl::text, '') as name
      from pg_attribute a
      join pg_class c on c.oid = a.attrelid
      join pg_namespace n on n.oid = c.relnamespace
      where a.attacl is not null and n.nspname not like 'pg_%'
        and n.nspname <> 'information_schema'
      union all
      -- A trigger attached to a baseline table creates no new object either.
      select 'trigger ' || n.nspname || '.' || c.relname || '.' || t.tgname as name
      from pg_trigger t
      join pg_class c on c.oid = t.tgrelid
      join pg_namespace n on n.oid = c.relnamespace
      where not t.tgisinternal and n.nspname not like 'pg_%'
        and n.nspname <> 'information_schema'`

    const baselineUrl = await shimOnlyDatabase('postdeck_baseline')
    let baseline: Set<string>
    try {
      baseline = await asAdmin(baselineUrl, async (q) =>
        new Set((await q(INVENTORY)).rows.map((r) => r.name as string)))
    } finally {
      await dropDatabase('postdeck_baseline')
    }

    const after = await asAdmin(url, async (q) =>
      (await q(INVENTORY)).rows.map((r) => r.name as string))

    // The schemas the checks in this file actually read. Kept as a literal list on
    // purpose: this is the one place where naming them is the POINT, because the
    // assertion is that nothing of ours lands outside them.
    const SCANNED = ['public.', 'app.', 'extensions.',
                     'schema public ', 'schema app ', 'schema extensions ',
                     'trigger public.', 'trigger app.', 'trigger extensions.']
    const outside = after
      .filter((name) => !baseline.has(name))
      .filter((name) => !SCANNED.some((prefix) => name.startsWith(prefix)))

    expect(outside, 'our migrations created or altered these objects in schemas no class test '
      + 'in this file examines, so nothing checks their RLS, grants or ownership').toEqual([])
  })

  test('no rewrite RULE redirects a write past the row level security on its target', async () => {
    // A RULE is not a relkind, so it escapes every check in this file by
    // construction. `CREATE RULE ... DO INSTEAD INSERT INTO public.posts` runs with
    // the RULE RELATION's owner's privileges -- the migration superuser -- so RLS on
    // public.posts is simply not applied. Verified: a member of BETA only had a
    // direct insert into an ALPHA post rejected, and the identical insert through a
    // staging table carrying such a rule landed in ALPHA.
    //
    // The automatic `_RETURN` rule is how Postgres implements every view; those are
    // covered by the view checks above. Any OTHER rule is banned, because a rule
    // cannot be reasoned about from the policies on the table it writes to.
    await asAdmin(url, async (q) => {
      const r = await q(`
        select n.nspname || '.' || c.relname as relation, r.rulename, r.ev_type
        from pg_rewrite r
        join pg_class c on c.oid = r.ev_class
        join pg_namespace n on n.oid = c.relnamespace
        where ${OUR_SCHEMAS} and not (r.rulename = '_RETURN' and r.ev_type = '1')
        order by 1, 2`)
      expect(r.rows, 'these rewrite rules can redirect a statement to another table, where the '
        + 'policies of the table the caller named no longer apply').toEqual([])
    })
  })

  test('every trigger function on our tables is one we reviewed', async () => {
    // Revoking EXECUTE does not stop a function running. Postgres checks EXECUTE at
    // CREATE TRIGGER time, not at fire time, so a SECURITY DEFINER function with
    // EXECUTE revoked from public, anon AND authenticated still runs on every insert
    // the caller makes. Verified: such a function copied every tenant's posts into a
    // table the caller could read, while the "only the intended roles can execute
    // anything" check reported false for all three roles and passed.
    //
    // The premise of that check -- a definer helper is safe if nobody can call it --
    // does not hold for trigger functions, so they are held to a named list instead.
    // Adding one here is a deliberate act that says someone read what it does.
    // Listed as `table -> function`, because BOTH halves matter. Filtering this
    // population by the TABLE's schema meant a definer trigger on `auth.users` --
    // a schema every real Supabase project has, and one this list excludes -- could
    // never appear in the enumerated set at all, so `.toEqual()` could not fail on
    // it. Verified: the query returned exactly these three rows while a trigger
    // `auth.users -> app.mirror_posts` sat alongside them, copying every tenant's
    // posts into the attacker's business on each new sign-up.
    const REVIEWED_TRIGGERS = [
      'public.audit_log -> app.audit_log_is_append_only',
      'public.audit_log -> app.audit_log_is_append_only',
      'public.business_members -> app.audit_row_change',
      'public.businesses -> app.audit_row_change',
      'public.posts -> app.audit_row_change',
      'public.posts -> app.pin_post_authorship',
      'public.scheduled_posts -> app.audit_row_change',
      'public.social_accounts -> app.audit_row_change',
    ]
    await asAdmin(url, async (q) => {
      // The population is every non-internal trigger that either RUNS one of our
      // functions or SITS ON one of our tables, whichever schema each is in.
      // Supabase's own triggers run Supabase's functions on Supabase's tables, so
      // they match neither half and are correctly left out.
      const r = await q(`
        select n.nspname || '.' || c.relname || ' -> ' || fn.nspname || '.' || f.proname as t
        from pg_trigger t
        join pg_class c on c.oid = t.tgrelid
        join pg_namespace n on n.oid = c.relnamespace
        join pg_proc f on f.oid = t.tgfoid
        join pg_namespace fn on fn.oid = f.pronamespace
        where not t.tgisinternal
          and (fn.nspname in ('app', 'public', 'extensions')
               or n.nspname in ('app', 'public', 'extensions'))
        order by 1`)
      expect(r.rows.map((x) => x.t), 'a trigger function runs regardless of who may EXECUTE it, '
        + 'so every trigger running our code -- or sitting on our tables -- has to be listed '
        + 'here by someone who read it').toEqual(REVIEWED_TRIGGERS)
    })
  })
})
