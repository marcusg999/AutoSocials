/**
 * Test harness for the database layer.
 *
 * These tests run against a REAL PostgreSQL server, not a mock. Supabase's own
 * pieces that plain Postgres lacks (auth.uid(), auth.jwt(), the anon/authenticated/
 * service_role roles, the Vault) are recreated by tests/db/supabase-shim.sql using
 * the same definitions Supabase uses, so an RLS policy that passes here is being
 * evaluated by the same engine and the same helper functions as in production.
 */
import { execSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { Client } from 'pg'
import { runMigrations } from '../../scripts/migrate'

const ADMIN_URL = process.env.ADMIN_DATABASE_URL ?? 'postgres://postdeck:postdeck@127.0.0.1:5432/postgres'

export function urlFor(dbName: string) {
  return ADMIN_URL.replace(/\/[^/]*$/, `/${dbName}`)
}

/** Drops and recreates a database, loads the Supabase shim, and migrates it up. */
export async function freshDatabase(dbName: string): Promise<string> {
  const admin = new Client({ connectionString: ADMIN_URL })
  await admin.connect()
  await admin.query(`drop database if exists ${dbName} with (force)`)
  await admin.query(`create database ${dbName}`)
  await admin.end()

  const url = urlFor(dbName)
  const shim = readFileSync(join(process.cwd(), 'tests/db/supabase-shim.sql'), 'utf8')
  const client = new Client({ connectionString: url })
  await client.connect()
  await client.query(shim)
  await client.end()

  await runMigrations(url, 'up')
  return url
}

export async function dropDatabase(dbName: string) {
  const admin = new Client({ connectionString: ADMIN_URL })
  await admin.connect()
  await admin.query(`drop database if exists ${dbName} with (force)`)
  await admin.end()
}

/**
 * Runs a block of queries as a signed-in Supabase user.
 *
 * `SET LOCAL ROLE authenticated` drops the superuser privileges the test connection
 * starts with, so RLS is genuinely enforced, and request.jwt.claims is the exact GUC
 * Supabase populates from the user's JWT. `aal` is the assurance level: 'aal1' is
 * password-only, 'aal2' is password plus a verified TOTP code.
 */
export async function asUser<T>(
  url: string,
  userId: string,
  aal: 'aal1' | 'aal2',
  work: (q: Query) => Promise<T>
): Promise<T> {
  const client = new Client({ connectionString: url })
  await client.connect()
  try {
    await client.query('begin')
    await client.query(`set local role authenticated`)
    await client.query(`select set_config('request.jwt.claims', $1, true)`, [
      JSON.stringify({ sub: userId, role: 'authenticated', aal }),
    ])
    const query: Query = (text, params) => client.query(text, params)
    const result = await work(query)
    await client.query('commit')
    return result
  } finally {
    await client.end()
  }
}

/** Runs a block as an anonymous (signed-out) visitor. */
export async function asAnon<T>(url: string, work: (q: Query) => Promise<T>): Promise<T> {
  const client = new Client({ connectionString: url })
  await client.connect()
  try {
    await client.query('begin')
    await client.query(`set local role anon`)
    const result = await work((text, params) => client.query(text, params))
    await client.query('commit')
    return result
  } finally {
    await client.end()
  }
}

/** Runs a block with full privileges, the way a trusted server-side worker would. */
export async function asAdmin<T>(url: string, work: (q: Query) => Promise<T>): Promise<T> {
  const client = new Client({ connectionString: url })
  await client.connect()
  try {
    return await work((text, params) => client.query(text, params))
  } finally {
    await client.end()
  }
}

export type Query = (text: string, params?: unknown[]) => Promise<{ rows: any[]; rowCount: number | null }>

/** Asserts that a query is refused, and returns the error for inspection. */
export async function expectRejected(run: () => Promise<unknown>): Promise<Error> {
  try {
    await run()
  } catch (err) {
    return err as Error
  }
  throw new Error('expected this write to be rejected, but it succeeded')
}
