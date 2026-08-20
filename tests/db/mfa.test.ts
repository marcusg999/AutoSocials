/**
 * QUALITY BAR #3 (database half): no data is reachable without password PLUS TOTP.
 *
 * The web app redirects a half-authenticated user to the MFA screen, but redirects
 * can be bypassed. These tests prove the last line of defence: even holding a valid
 * session cookie, a user who has not passed a TOTP challenge (aal1) gets nothing
 * out of the database and cannot write to it -- enforced by a RESTRICTIVE policy
 * on every table, which no future permissive policy can widen.
 */
import { beforeAll, afterAll, describe, expect, test } from 'vitest'
import { asAdmin, asUser, dropDatabase, expectRejected, freshDatabase } from './helpers'

const DB = 'postdeck_mfa_test'
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
    await q(`insert into public.posts (business_id, created_by, body) values ($1,$2,'{"text":"members only"}')`, [businessA, ALICE])
  })
}, 60_000)

afterAll(async () => { await dropDatabase(DB) })

test('the harness really does drop superuser privileges (otherwise every test below is meaningless)', async () => {
  await asUser(url, ALICE, 'aal2', async (q) => {
    const r = await q(`select current_user as who, (select count(*) from pg_roles where rolname = current_user and rolsuper) as is_super`)
    expect(r.rows[0].who).toBe('authenticated')
    expect(Number(r.rows[0].is_super)).toBe(0)
  })
})

describe('a password-only session (aal1) is refused everywhere', () => {
  test.each([
    ['businesses',       `select * from public.businesses`],
    ['business_members', `select * from public.business_members`],
    ['social_accounts',  `select * from public.social_accounts`],
    ['posts',            `select * from public.posts`],
    ['scheduled_posts',  `select * from public.scheduled_posts`],
    ['audit_log',        `select * from public.audit_log`],
  ])('aal1 reads zero rows from %s even as a genuine member', async (_t, sql) => {
    await asUser(url, ALICE, 'aal1', async (q) => {
      expect((await q(sql)).rowCount).toBe(0)
    })
  })

  test('aal1 cannot write, even into a business the user genuinely owns', async () => {
    await asUser(url, ALICE, 'aal1', async (q) => {
      const err = await expectRejected(() =>
        q(`insert into public.posts (business_id, created_by, body) values ($1,$2,'{}')`, [businessA, ALICE]))
      expect(err.message).toMatch(/row-level security/i)
    })
  })

  test('a JWT with no aal claim at all is treated as aal1, not as trusted', async () => {
    // Missing claim must fail closed. app.has_completed_mfa() defaults to 'aal1'.
    const { Client } = await import('pg')
    const client = new Client({ connectionString: url })
    await client.connect()
    try {
      await client.query('begin')
      await client.query('set local role authenticated')
      await client.query(`select set_config('request.jwt.claims', $1, true)`, [
        JSON.stringify({ sub: ALICE, role: 'authenticated' }), // no aal key
      ])
      const r = await client.query(`select * from public.posts`)
      expect(r.rowCount).toBe(0)
    } finally { await client.end() }
  })
})

describe('the same session after passing TOTP (aal2) works normally', () => {
  test('aal2 reads the member\'s rows', async () => {
    await asUser(url, ALICE, 'aal2', async (q) => {
      expect((await q(`select * from public.posts`)).rowCount).toBe(1)
    })
  })
})

test('the MFA gate is RESTRICTIVE on every table, so no later policy can widen it', async () => {
  await asAdmin(url, async (q) => {
    const r = await q(`
      select tablename from pg_policies
      where schemaname='public' and policyname='mfa_required' and permissive='RESTRICTIVE'
      order by tablename`)
    expect(r.rows.map((x) => x.tablename)).toEqual([
      'audit_log', 'business_members', 'businesses', 'posts', 'scheduled_posts', 'social_accounts',
    ])
  })
})

test('every business-scoped table has RLS enabled and forced', async () => {
  await asAdmin(url, async (q) => {
    const r = await q(`
      select relname, relrowsecurity, relforcerowsecurity
      from pg_class c join pg_namespace n on n.oid=c.relnamespace
      where n.nspname='public' and c.relkind='r'
        and relname in ('businesses','business_members','social_accounts','posts','scheduled_posts','audit_log')
      order by relname`)
    expect(r.rowCount).toBe(6)
    for (const row of r.rows) {
      expect(row.relrowsecurity, `${row.relname} RLS enabled`).toBe(true)
      expect(row.relforcerowsecurity, `${row.relname} RLS forced`).toBe(true)
    }
  })
})
