/**
 * Migration runner.
 *
 * Every migration is a pair of files: 0007_name.sql applies it, 0007_name.down.sql
 * undoes it. Applied migrations are recorded in schema_migrations so `up` is safe
 * to run repeatedly, and `down` unwinds them newest-first.
 *
 *   npm run db:up      apply everything not yet applied
 *   npm run db:down    roll back every applied migration, newest first
 *   npm run db:reset   down then up
 */
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { Client } from 'pg'

const MIGRATIONS_DIR = join(process.cwd(), 'supabase', 'migrations')

type Migration = { version: string; name: string; upFile: string; downFile: string }

function loadMigrations(): Migration[] {
  const files = readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith('.sql'))
  const ups = files.filter((f) => !f.endsWith('.down.sql')).sort()
  return ups.map((upFile) => {
    const name = upFile.replace(/\.sql$/, '')
    const downFile = `${name}.down.sql`
    if (!files.includes(downFile)) {
      throw new Error(`${upFile} has no matching ${downFile} — every migration must be reversible`)
    }
    // Keyed on the whole filename, not just the numeric prefix: two migrations
    // sharing a prefix would otherwise silently collide in the ledger.
    return { version: name, name, upFile, downFile }
  })
}

async function ensureLedger(client: Client) {
  await client.query(`
    create table if not exists public.schema_migrations (
      version    text primary key,
      name       text not null,
      applied_at timestamptz not null default now()
    )`)
}

async function appliedVersions(client: Client): Promise<Set<string>> {
  const { rows } = await client.query<{ version: string }>('select version from public.schema_migrations')
  return new Set(rows.map((r) => r.version))
}

async function up(client: Client) {
  await ensureLedger(client)
  const applied = await appliedVersions(client)
  for (const m of loadMigrations()) {
    if (applied.has(m.version)) {
      console.log(`  skip  ${m.name} (already applied)`)
      continue
    }
    const sql = readFileSync(join(MIGRATIONS_DIR, m.upFile), 'utf8')
    // Each migration is one transaction: it applies completely or not at all.
    await client.query('begin')
    try {
      await client.query(sql)
      await client.query('insert into public.schema_migrations (version, name) values ($1, $2)', [m.version, m.name])
      await client.query('commit')
      console.log(`  up    ${m.name}`)
    } catch (err) {
      await client.query('rollback')
      throw new Error(`migration ${m.name} failed: ${(err as Error).message}`)
    }
  }
}

async function down(client: Client) {
  await ensureLedger(client)
  const applied = await appliedVersions(client)
  for (const m of loadMigrations().reverse()) {
    if (!applied.has(m.version)) continue
    const sql = readFileSync(join(MIGRATIONS_DIR, m.downFile), 'utf8')
    await client.query('begin')
    try {
      await client.query(sql)
      await client.query('delete from public.schema_migrations where version = $1', [m.version])
      await client.query('commit')
      console.log(`  down  ${m.name}`)
    } catch (err) {
      await client.query('rollback')
      throw new Error(`rollback of ${m.name} failed: ${(err as Error).message}`)
    }
  }
}

export async function runMigrations(connectionString: string, direction: 'up' | 'down' | 'reset') {
  const client = new Client({ connectionString })
  await client.connect()
  try {
    if (direction === 'reset') {
      await down(client)
      await up(client)
    } else if (direction === 'up') {
      await up(client)
    } else {
      await down(client)
    }
  } finally {
    await client.end()
  }
}

// Run the CLI only when this file is the entry point, not when a test imports it.
const invokedDirectly =
  process.argv[1] !== undefined &&
  import.meta.url === new URL(`file://${process.argv[1]}`).href

if (invokedDirectly) {
  const direction = (process.argv[2] ?? 'up') as 'up' | 'down' | 'reset'
  const url = process.env.DATABASE_URL
  if (!url) {
    console.error('DATABASE_URL is not set')
    process.exit(1)
  }
  runMigrations(url, direction).then(
    () => console.log(`migrations ${direction}: ok`),
    (err) => { console.error(err.message); process.exit(1) }
  )
}
