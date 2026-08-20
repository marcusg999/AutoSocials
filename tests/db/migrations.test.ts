/**
 * QUALITY BAR #5: migrations run clean on an empty database and roll back cleanly.
 */
import { afterAll, expect, test } from 'vitest'
import { Client } from 'pg'
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { runMigrations } from '../../scripts/migrate'
import { dropDatabase, urlFor } from './helpers'

const DB = 'postdeck_migration_test'
const ADMIN_URL = process.env.ADMIN_DATABASE_URL ?? 'postgres://postdeck:postdeck@127.0.0.1:5432/postgres'

afterAll(async () => { await dropDatabase(DB) })

async function emptyDatabaseWithShim() {
  const admin = new Client({ connectionString: ADMIN_URL })
  await admin.connect()
  await admin.query(`drop database if exists ${DB} with (force)`)
  await admin.query(`create database ${DB}`)
  await admin.end()
  const url = urlFor(DB)
  const c = new Client({ connectionString: url })
  await c.connect()
  await c.query(readFileSync(join(process.cwd(), 'tests/db/supabase-shim.sql'), 'utf8'))
  await c.end()
  return url
}

async function query(url: string, sql: string) {
  const c = new Client({ connectionString: url })
  await c.connect()
  try { return (await c.query(sql)).rows } finally { await c.end() }
}

test('every migration has a matching rollback file', () => {
  const dir = join(process.cwd(), 'supabase/migrations')
  const files = readdirSync(dir)
  const ups = files.filter((f) => f.endsWith('.sql') && !f.endsWith('.down.sql'))
  expect(ups.length).toBeGreaterThan(0)
  for (const up of ups) {
    expect(files, `${up} needs a rollback`).toContain(up.replace(/\.sql$/, '.down.sql'))
  }
})

test('up, down and up again all run clean, leaving nothing behind', async () => {
  const url = await emptyDatabaseWithShim()

  await runMigrations(url, 'up')
  const afterUp = await query(url, `select table_name from information_schema.tables where table_schema='public' order by 1`)
  expect(afterUp.map((r) => r.table_name)).toEqual([
    'audit_log', 'business_members', 'businesses', 'posts',
    'scheduled_posts', 'schema_migrations', 'social_accounts',
  ])

  // Running up a second time must be a no-op, not an error.
  await runMigrations(url, 'up')

  await runMigrations(url, 'down')
  const afterDown = await query(url, `select table_name from information_schema.tables where table_schema='public' order by 1`)
  expect(afterDown.map((r) => r.table_name)).toEqual(['schema_migrations'])

  const leftoverTypes = await query(url, `select typname from pg_type t join pg_namespace n on n.oid=t.typnamespace where n.nspname='public' and t.typtype='e'`)
  expect(leftoverTypes).toEqual([])

  const leftoverSchema = await query(url, `select nspname from pg_namespace where nspname='app'`)
  expect(leftoverSchema).toEqual([])

  // And it must come back up cleanly on the now-empty database.
  await runMigrations(url, 'up')
  const afterReUp = await query(url, `select count(*)::int as n from public.businesses`)
  expect(afterReUp[0].n).toBe(7)
}, 120_000)

test('the seed creates exactly the seven named businesses, and re-seeding does not duplicate them', async () => {
  const url = urlFor(DB)
  await runMigrations(url, 'up')
  const rows = await query(url, `select name from public.businesses order by name`)
  expect(rows.map((r) => r.name)).toEqual([
    'BUSINESS_1', 'BUSINESS_2', 'BUSINESS_3', 'BUSINESS_4', 'BUSINESS_5', 'BUSINESS_6', 'BUSINESS_7',
  ])
})

test('the seed rollback never destroys a business that is actually in use', async () => {
  // 0009's rollback deletes seeded businesses by name, and `businesses` cascades to
  // members, posts and connected accounts. Run carelessly against a live database
  // that would silently wipe real customer data, so it skips anything in use.
  const url = urlFor(DB)
  await runMigrations(url, 'up')

  const c = new Client({ connectionString: url })
  await c.connect()
  try {
    const userId = '55555555-5555-5555-5555-555555555555'
    await c.query(`insert into auth.users (id, email) values ($1,'in-use@example.com') on conflict do nothing`, [userId])
    const inUse = (await c.query(`select id from public.businesses where name = 'BUSINESS_1'`)).rows[0].id
    await c.query(`insert into public.business_members (business_id, user_id, role) values ($1,$2,'owner')`, [inUse, userId])
    await c.query(`insert into public.posts (business_id, created_by, body) values ($1,$2,'{"real":"work"}')`, [inUse, userId])

    // Apply just the seed rollback.
    await c.query(readFileSync(join(process.cwd(), 'supabase/migrations/0009_seed_businesses.down.sql'), 'utf8'))

    const survived = await c.query(`select count(*)::int n from public.businesses where id = $1`, [inUse])
    expect(survived.rows[0].n, 'a business with real data must not be deleted by a rollback').toBe(1)
    const postsKept = await c.query(`select count(*)::int n from public.posts where business_id = $1`, [inUse])
    expect(postsKept.rows[0].n, 'its posts must not be cascade-deleted').toBe(1)

    // The six untouched seed businesses are fair game and should be gone.
    const remaining = await c.query(`select count(*)::int n from public.businesses where name like 'BUSINESS_%'`)
    expect(remaining.rows[0].n).toBe(1)
  } finally {
    await c.end()
  }
}, 120_000)
