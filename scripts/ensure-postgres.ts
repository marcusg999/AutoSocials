/**
 * Make sure there is a Postgres to test against, and start one if there is not.
 *
 * The database tests need a real server — they create and drop their own scratch
 * databases and connect as a real `authenticated` role, which is the whole reason
 * they prove anything. On a machine where the server happens to be stopped, that
 * came out as six test files failing with ECONNREFUSED, which reads like the app
 * is broken rather than like a service is not running.
 *
 * So this runs first and says one of three things: it was already up, it started
 * it, or it could not — and in the last case it names exactly what it tried.
 *
 * Two rules it follows, both learned the hard way elsewhere in this project:
 *
 *   - It enumerates rather than guesses. Cluster versions and Homebrew service
 *     names are read out of the tools that know them, never constructed from a
 *     version number somebody hardcoded.
 *   - It tells the difference between "nothing is listening" and "something is
 *     listening and said no". A server that is up but rejecting the credentials is
 *     not a server that needs starting, and starting it again would fix nothing
 *     while hiding the real message.
 */
import { execFileSync } from 'node:child_process'
import { Client } from 'pg'

const ADMIN_URL =
  process.env.ADMIN_DATABASE_URL ?? 'postgres://postdeck:postdeck@127.0.0.1:5432/postgres'

/** How long to keep asking after a start, before calling it a failure. */
const READY_TIMEOUT_MS = 20_000
const POLL_MS = 500

export type Reachability = 'reachable' | 'unreachable' | 'refused-credentials' | 'other'

/**
 * What a failed connection actually means.
 *
 * Postgres reports "no server" and "server said no" through completely different
 * channels — one is a socket error from the OS, the other is an authentication
 * error from a server that answered — and only the first is worth starting
 * anything for.
 */
export function classifyConnectionError(error: unknown): Reachability {
  const code = (error as { code?: string })?.code ?? ''
  const message = (error as { message?: string })?.message ?? ''

  // ECONNREFUSED: nothing on the port. ENOENT: no socket file. EHOSTUNREACH /
  // ETIMEDOUT: not this machine's problem, but still nothing listening for us.
  if (['ECONNREFUSED', 'ENOENT', 'EHOSTUNREACH', 'ETIMEDOUT', 'ECONNRESET'].includes(code)) {
    return 'unreachable'
  }
  // 28P01 invalid_password, 28000 invalid_authorization_specification, 3D000
  // database does not exist. All of them mean a server answered.
  if (['28P01', '28000', '3D000'].includes(code)) return 'refused-credentials'
  if (/does not exist|password authentication failed|role .* does not exist/i.test(message)) {
    return 'refused-credentials'
  }
  return 'other'
}

/** One connection attempt, with the reason it failed when it does. */
async function probe(): Promise<{ state: Reachability; detail: string }> {
  const client = new Client({ connectionString: ADMIN_URL, connectionTimeoutMillis: 3000 })
  try {
    await client.connect()
    await client.query('select 1')
    return { state: 'reachable', detail: '' }
  } catch (error) {
    return {
      state: classifyConnectionError(error),
      detail: error instanceof Error ? error.message : String(error),
    }
  } finally {
    await client.end().catch(() => {})
  }
}

function have(command: string): boolean {
  try {
    execFileSync('command', ['-v', command], { stdio: 'ignore', shell: true })
    return true
  } catch {
    return false
  }
}

function run(command: string, args: string[]): void {
  execFileSync(command, args, { stdio: 'inherit' })
}

// ---------------------------------------------------------------------------
// Reading the tools that know, rather than guessing
// ---------------------------------------------------------------------------

export type Cluster = { version: string; name: string; status: string }

/**
 * Parses `pg_lsclusters`, which prints a header line and then one cluster per row:
 *
 *   Ver Cluster Port Status Owner    Data directory ...
 *   16  main    5432 down   postgres /var/lib/postgresql/16/main ...
 *
 * Read rather than assumed, because the version in that first column is exactly
 * the sort of thing that gets hardcoded as 16 and then breaks on 17.
 */
export function parseClusters(output: string): Cluster[] {
  return output
    .split('\n')
    .slice(1)
    .map((line) => line.trim())
    .filter((line) => line !== '')
    .map((line) => line.split(/\s+/))
    .filter((columns) => columns.length >= 4)
    .map((columns) => ({ version: columns[0]!, name: columns[1]!, status: columns[3]! }))
}

export type BrewService = { name: string; status: string }

/**
 * Parses `brew services list`:
 *
 *   Name          Status  User  File
 *   postgresql@16 none    marcus ...
 */
export function parseBrewServices(output: string): BrewService[] {
  return output
    .split('\n')
    .slice(1)
    .map((line) => line.trim())
    .filter((line) => line !== '')
    .map((line) => line.split(/\s+/))
    .filter((columns) => columns.length >= 2)
    .map((columns) => ({ name: columns[0]!, status: columns[1]! }))
}

/** Homebrew names its Postgres formulae postgresql@NN; anything else is not one. */
export function isPostgresService(name: string): boolean {
  return /^postgresql(@\d+(\.\d+)?)?$/.test(name)
}

// ---------------------------------------------------------------------------
// Ways to start one. Tried in order; each says whether it applies.
// ---------------------------------------------------------------------------

type Strategy = { name: string; attempt: () => boolean }

const STRATEGIES: Strategy[] = [
  {
    // Debian and Ubuntu, including the container this repo is developed in.
    name: 'pg_ctlcluster (Debian/Ubuntu)',
    attempt() {
      if (!have('pg_lsclusters') || !have('pg_ctlcluster')) return false

      const clusters = parseClusters(
        execFileSync('pg_lsclusters', [], { encoding: 'utf8' }))
      const down = clusters.filter((cluster) => cluster.status !== 'online')
      if (down.length === 0) return false

      for (const cluster of down) {
        console.log(`  starting cluster ${cluster.version}/${cluster.name}...`)
        // Root in a container, sudo on a workstation. If neither works the error
        // is printed and the next cluster (or the next strategy) is tried.
        try {
          if (process.getuid?.() === 0) run('pg_ctlcluster', [cluster.version, cluster.name, 'start'])
          else run('sudo', ['-n', 'pg_ctlcluster', cluster.version, cluster.name, 'start'])
          return true
        } catch {
          console.log(`  could not start ${cluster.version}/${cluster.name}`)
        }
      }
      return false
    },
  },
  {
    name: 'brew services (macOS)',
    attempt() {
      if (!have('brew')) return false

      const services = parseBrewServices(
        execFileSync('brew', ['services', 'list'], { encoding: 'utf8' }))
      const postgres = services.find(
        (service) => isPostgresService(service.name) && service.status !== 'started')
      if (!postgres) return false

      console.log(`  starting ${postgres.name} with brew services...`)
      run('brew', ['services', 'start', postgres.name])
      return true
    },
  },
  {
    // Only an existing container, never `docker run`: creating one would invent a
    // database whose password and volume this script chose on your behalf.
    name: 'docker start (an existing container)',
    attempt() {
      if (!have('docker')) return false
      const container = process.env.POSTDECK_PG_CONTAINER ?? 'postdeck-postgres'

      // The CLI being installed says nothing about the daemon running. A machine
      // with Docker Desktop shut down is not a failure worth printing — this
      // strategy simply does not apply, so ask quietly and move on.
      let existing: string
      try {
        existing = execFileSync(
          'docker', ['ps', '-a', '--filter', `name=^/${container}$`, '--format', '{{.Names}}'],
          { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim()
      } catch {
        return false
      }
      if (existing === '') return false

      console.log(`  starting container ${container}...`)
      run('docker', ['start', container])
      return true
    },
  },
]

async function waitUntilReady(): Promise<boolean> {
  const deadline = Date.now() + READY_TIMEOUT_MS
  while (Date.now() < deadline) {
    const { state } = await probe()
    // refused-credentials means it is up. Wrong credentials are a different
    // problem, reported by the caller rather than waited out here.
    if (state === 'reachable' || state === 'refused-credentials') return true
    await new Promise((resolve) => setTimeout(resolve, POLL_MS))
  }
  return false
}

async function main(): Promise<void> {
  const where = ADMIN_URL.replace(/\/\/[^@]*@/, '//***@')
  const first = await probe()

  if (first.state === 'reachable') {
    console.log(`Postgres is up at ${where}`)
    return
  }

  if (first.state === 'refused-credentials') {
    // Starting anything here would be the wrong move: something IS listening.
    console.error(`Postgres is running at ${where} but refused the connection:`)
    console.error(`  ${first.detail}`)
    console.error('')
    console.error('The server is up, so this is a role, password or database problem,')
    console.error('not a stopped service. Check ADMIN_DATABASE_URL.')
    process.exit(1)
  }

  if (first.state === 'other') {
    console.error(`Could not reach Postgres at ${where}, and the error is not one this`)
    console.error('script knows how to act on:')
    console.error(`  ${first.detail}`)
    process.exit(1)
  }

  console.log(`Nothing listening at ${where}. Trying to start one.`)

  const tried: string[] = []
  for (const strategy of STRATEGIES) {
    tried.push(strategy.name)
    let started = false
    try {
      started = strategy.attempt()
    } catch (error) {
      console.log(`  ${strategy.name} failed: ${error instanceof Error ? error.message : error}`)
      continue
    }
    if (!started) continue

    if (await waitUntilReady()) {
      console.log(`Postgres is up at ${where} (started with ${strategy.name})`)
      return
    }
    console.log(`  ${strategy.name} ran but nothing came up within ${READY_TIMEOUT_MS / 1000}s`)
  }

  console.error('')
  console.error(`Could not start a Postgres for ${where}. Tried:`)
  for (const name of tried) console.error(`  - ${name}`)
  console.error('')
  console.error('Start one yourself, or point ADMIN_DATABASE_URL at one that is running.')
  console.error('The database tests create and drop their own scratch databases, so any')
  console.error('server you can connect to as a superuser will do.')
  process.exit(1)
}

// Guarded so the pure helpers above can be imported by a test without this running.
if (process.argv[1]?.endsWith('ensure-postgres.ts')) {
  main().catch((error) => {
    console.error(error)
    process.exit(1)
  })
}
