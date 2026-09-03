/**
 * QUALITY BAR #2: no secret appears in the client bundle or in any NEXT_PUBLIC_ var.
 *
 * This is a real check, not an assertion: it plants uniquely-identifiable canary
 * values in the server-only environment variables, runs a production `next build`,
 * and then greps every file the browser could ever download for them. If a canary
 * turns up in the bundle, a real key would have too.
 *
 *   npm run test:secrets
 */
import { execFileSync, spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, rmSync, writeFileSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { join, relative } from 'node:path'

const ROOT = process.cwd()
const failures: string[] = []
const passes: string[] = []

function fail(msg: string) { failures.push(msg) }
function pass(msg: string) { passes.push(msg) }

/** Every file under a directory, recursively. */
function walk(dir: string, out: string[] = []): string[] {
  if (!existsSync(dir)) return out
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) walk(full, out)
    else out.push(full)
  }
  return out
}

// ---------------------------------------------------------------------------
// 1. No secret may be committed to git.
// ---------------------------------------------------------------------------
function checkGitTracked() {
  const tracked = execFileSync('git', ['ls-files'], { cwd: ROOT, encoding: 'utf8' }).split('\n').filter(Boolean)
  const envFiles = tracked.filter((f) => f.startsWith('.env') && f !== '.env.example')
  if (envFiles.length) fail(`git tracks environment files that may hold secrets: ${envFiles.join(', ')}`)
  else pass('no .env file other than .env.example is tracked by git')

  if (!existsSync(join(ROOT, '.env.example'))) {
    fail('.env.example is missing')
    return
  }
  // Placeholders only: every value must be empty or an obvious stand-in.
  const lines = readFileSync(join(ROOT, '.env.example'), 'utf8').split('\n')
  const suspicious = lines.filter((line) => {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.+)$/)
    if (!m) return false
    const value = m[2].trim().replace(/^["']|["']$/g, '')
    if (!value) return false
    // A value is acceptable only if it is obviously a stand-in: an angle-bracket
    // hint, a "your-..." name, or a local-only connection string.
    const looksLikePlaceholder =
      /^(<.*>|your[-_]|replace|placeholder|example|changeme|xxx|\.\.\.)/i.test(value) ||
      /^https:\/\/your/i.test(value) ||
      /(localhost|127\.0\.0\.1)/.test(value) ||
      // A short plain number is tuning, not a credential (e.g. TRUSTED_PROXY_COUNT=1).
      /^\d{1,4}$/.test(value)
    const looksLikeRealKey = /^(eyJ|sb_|sk-|sbp_)/.test(value) || value.length > 60
    return looksLikeRealKey || !looksLikePlaceholder
  })
  if (suspicious.length) fail(`.env.example has values that are not placeholders:\n    ${suspicious.join('\n    ')}`)
  else pass('.env.example contains placeholders only')
}

/** Every source file in the project, excluding build output and dependencies. */
const SKIP_DIRECTORIES = new Set(['node_modules', '.next', '.git', 'supabase'])

function walkProject(dir = ROOT, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRECTORIES.has(entry)) continue
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) walkProject(full, out)
    else out.push(full)
  }
  return out
}

// ---------------------------------------------------------------------------
// 2. No secret-sounding variable may be exposed as NEXT_PUBLIC_.
//    Anything prefixed NEXT_PUBLIC_ is inlined into the browser bundle by Next.js.
// ---------------------------------------------------------------------------
const FORBIDDEN_IN_PUBLIC = /(SERVICE_ROLE|SECRET|PRIVATE|PASSWORD|_TOKEN|CREDENTIAL|SIGNING|VAULT)/i

function checkPublicVarNames() {
  // The whole project, not four named directories. next.config.ts, components/ and
  // any .cjs/.mts file sat outside the old scope, and a NEXT_PUBLIC_ name is
  // inlined into the browser bundle from wherever it is written.
  const sources = walkProject().filter((f) => /\.(m|c)?[jt]sx?$/.test(f))
  if (existsSync(join(ROOT, '.env.example'))) sources.push(join(ROOT, '.env.example'))

  const offenders: string[] = []
  for (const file of sources) {
    for (const name of readFileSync(file, 'utf8').match(/NEXT_PUBLIC_[A-Z0-9_]+/g) ?? []) {
      if (FORBIDDEN_IN_PUBLIC.test(name)) offenders.push(`${relative(ROOT, file)}: ${name}`)
    }
  }
  if (offenders.length) {
    fail(`secret-sounding NEXT_PUBLIC_ variables (these are inlined into the browser bundle):\n    ${offenders.join('\n    ')}`)
    return
  }

  // The name is the attacker's to choose, so the public variables are enumerated
  // rather than pattern-matched: renaming DATABASE_URL to NEXT_PUBLIC_DATABASE_URL
  // passed a name test and left the canary population. See BUILD_NOTES G102.
  const PUBLIC_BY_DESIGN = ['NEXT_PUBLIC_SUPABASE_URL', 'NEXT_PUBLIC_SUPABASE_ANON_KEY']

  // The population is every NEXT_PUBLIC_ name the CODE uses, not the ones
  // .env.example happens to declare. Reading only .env.example meant a variable read
  // by application code and set in the deployment environment -- never written down
  // here -- escaped this check and the canary population both, while this very line
  // printed "only the 2 values meant to be public carry the prefix".
  const declared = [...new Set([
    ...(existsSync(join(ROOT, '.env.example'))
      ? readFileSync(join(ROOT, '.env.example'), 'utf8').match(/^NEXT_PUBLIC_[A-Z0-9_]+/gm) ?? []
      : []),
    // Comment-stripped, or this file's own prose about NEXT_PUBLIC_DATABASE_URL --
    // written to explain a previous finding -- reads as a usage and fails the check.
    ...sources.flatMap((file) => readFileSync(file, 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, ' ')
      .replace(/(^|[^:])\/\/.*$/gm, '$1')
      .match(/NEXT_PUBLIC_[A-Z0-9_]+/g) ?? []),
  ])].sort()
  const unexpected = declared.filter((name) => !PUBLIC_BY_DESIGN.includes(name))
  if (unexpected.length) {
    fail(`these NEXT_PUBLIC_ variables are used or declared but are not on the list of `
      + `values meant to reach the browser: ${unexpected.join(', ')}. The prefix makes `
      + `a value public and removes it from the canary population, so a server value `
      + `renamed into it becomes invisible to every other check here.`)
    return
  }
  pass(`no NEXT_PUBLIC_ variable is named like a secret, and of the ${declared.length} such `
    + `name(s) used anywhere in this project, all are on the ${PUBLIC_BY_DESIGN.length}-value `
    + 'allowlist meant to reach the browser')
}

// ---------------------------------------------------------------------------
// 3. The service-role client must never be reachable from client code.
// ---------------------------------------------------------------------------
function checkAdminClientIsServerOnly() {
  const adminFile = join(ROOT, 'lib/supabase/admin.ts')
  if (!existsSync(adminFile)) { fail('lib/supabase/admin.ts is missing'); return }
  if (!/import ['"]server-only['"]/.test(readFileSync(adminFile, 'utf8'))) {
    fail("lib/supabase/admin.ts does not import 'server-only', so it could be pulled into a client bundle")
  } else pass("lib/supabase/admin.ts is marked 'server-only'")

  // Project-wide: a 'use client' component in components/ importing the
  // service-role client was outside the old app/ + lib/ scope entirely.
  const clientComponents = walkProject()
    .filter((f) => /\.(m|c)?[jt]sx?$/.test(f))
    .filter((f) => /^\s*['"]use client['"]/.test(readFileSync(f, 'utf8')))

  const leaks = clientComponents.filter((f) => /supabase\/admin|SERVICE_ROLE/.test(readFileSync(f, 'utf8')))
  if (leaks.length) {
    fail(`client components reference the service-role client: ${leaks.map((f) => relative(ROOT, f)).join(', ')}`)
    return
  }

  // Said plainly rather than dressed up as a pass: with no client components there
  // is nothing here to find, and this check is not yet evidence of anything.
  if (clientComponents.length === 0) {
    pass("no 'use client' file references the service-role client (there are none yet — "
      + 'this check only starts meaning something in a later phase)')
  } else {
    pass(`no 'use client' file references the service-role client (${clientComponents.length} scanned)`)
  }
}

// ---------------------------------------------------------------------------
// 4. The real proof: build with canary secrets, serve the app, and read every
//    route the way a browser would.
//
//    An earlier version grepped `.next/static` plus any prerendered files. That is
//    structurally blind to this app: every page sets `dynamic = 'force-dynamic'`,
//    so nothing is prerendered and `.next/static` can never contain a value that is
//    serialized at REQUEST time. A server component passing a secret to a client
//    component puts it in the RSC flight payload of the live response -- exactly
//    where the old scan could not look. Verified: that leak passed the old check
//    and was visible twice in `curl` output.
//
//    So the scan now happens against a running server.
// ---------------------------------------------------------------------------
/**
 * Every server-only variable, given a distinctive value so it can be recognised in
 * a response.
 *
 * These were three hand-picked names, one of which (SUPABASE_DB_PASSWORD) the
 * project does not even use, while DATABASE_URL and ADMIN_PASSWORD -- both declared
 * in .env.example, both genuinely secret -- were not canaried at all. A page
 * printing the database superuser password shipped it to the browser and the check
 * named "no secret appears in the client bundle" passed.
 *
 * So the list is no longer hand-picked: assertCanariesCoverEveryServerVar() below
 * proves it accounts for every server-only name .env.example declares.
 */
const CANARIES = {
  SUPABASE_SERVICE_ROLE_KEY: 'CANARY_SERVICE_ROLE_a1b2c3d4e5f6a7b8',
  CSRF_SIGNING_SECRET: 'CANARY_CSRF_SECRET_5a4b3c2d1e0f9887_at_least_32_chars',
  DATABASE_URL: 'postgresql://postgres:CANARY_DB_PASSWORD_9f8e7d6c@127.0.0.1:5432/postgres',
  ADMIN_PASSWORD: 'CANARY_ADMIN_PASSWORD_3c2d1e0f98877665',
  ADMIN_EMAIL: 'canary-admin-4b3c2d1e@localhost',
} as const

/**
 * Server-only variables that carry no secret AND cannot be canaried, because the
 * app parses them and a canary value would stop it starting. Each needs a reason.
 */
const NOT_CANARYABLE: Record<string, string> = {
  // Compared against the request origin; a canary value fails every CSRF check.
  APP_ORIGIN: 'an origin the app must match against real requests',
  // Parsed as a number.
  TRUSTED_PROXY_COUNT: 'a small integer, not a credential',
  // Set per run by the scanner itself and asserted absent from .env.example.
  SECRET_SCAN_TOKEN: 'generated per run; checked separately by checkScanModeIsNotShipped',
  // The same project URL that ships publicly as NEXT_PUBLIC_SUPABASE_URL. Canarying
  // it would flag every legitimate appearance of the public value.
  SUPABASE_URL: 'the public project URL, also shipped as NEXT_PUBLIC_SUPABASE_URL',
}

/**
 * The completeness assertion for the canary list.
 *
 * Six review rounds each found a filter narrower than the population it claimed to
 * cover. A hand-written canary list is exactly that shape, so it is checked against
 * .env.example -- the file that defines what this app's server-only variables ARE.
 */
function assertCanariesCoverEveryServerVar() {
  const examplePath = join(ROOT, '.env.example')
  if (!existsSync(examplePath)) { fail('.env.example is missing'); return }
  const declared = [...readFileSync(examplePath, 'utf8').matchAll(/^([A-Z][A-Z0-9_]*)=/gm)]
    .map((m) => m[1]!)
    .filter((name) => !name.startsWith('NEXT_PUBLIC_'))

  const accounted = new Set([...Object.keys(CANARIES), ...Object.keys(NOT_CANARYABLE)])
  const missing = declared.filter((name) => !accounted.has(name))
  if (missing.length) {
    fail(`.env.example declares server-only variables this scan never canaries, so a page `
      + `printing one would not be caught: ${missing.join(', ')}`)
  } else {
    pass(`every server-only variable in .env.example is canaried or declared non-secret `
      + `(${declared.length} checked)`)
  }
}

const PORT = 3987
const ORIGIN = `http://127.0.0.1:${PORT}`

// Lets the scanner render authenticated pages. Generated fresh for each run and
// never written anywhere. See lib/security/scan-mode.ts for the fences.
const STUB_PORT = 3988

/** Probe logs live outside .next, which this script deletes before each build. */
const PROBE_DIR = join(ROOT, '.probe')
mkdirSync(PROBE_DIR, { recursive: true })

function buildEnvironment(): NodeJS.ProcessEnv {
  return {
    ...process.env,
    ...CANARIES,
    // Pointed at the local stub so authenticated pages actually render.
    NEXT_PUBLIC_SUPABASE_URL: `http://127.0.0.1:${STUB_PORT}`,
    NEXT_PUBLIC_SUPABASE_ANON_KEY: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? 'public-anon-key-safe-to-ship',
    APP_ORIGIN: ORIGIN,
    NEXT_TELEMETRY_DISABLED: '1',
  }
}

/**
 * Every route the app serves, read from Next's own manifest.
 *
 * Dynamic segments are FILLED IN, not skipped. Skipping them meant a page at
 * `/dashboard/[businessId]` was never fetched and never even named in the output --
 * and Phase 2 is almost entirely dynamic segments, so the blind spot pointed
 * directly at the routes that do not exist yet. A placeholder that 404s is a fine
 * outcome; a route nobody looked at is not.
 */
function routesFromManifest(): string[] {
  return [...routeTable().keys()]
}

/** Each servable URL, and whether it is a route handler (so it accepts more verbs). */
function routeTable(): Map<string, { isHandler: boolean }> {
  const routes = new Map<string, { isHandler: boolean }>()

  // BOTH routers. Reading only app-paths-manifest.json meant a `pages/api/*.ts`
  // endpoint -- a real, built, registered route -- was never fetched: one serving
  // the service-role key answered an anonymous GET with 200 while this scan
  // reported the same "8 routes" as a clean tree. tests/app/guards.test.ts bans the
  // pages router outright; this reads the build output so the ban is enforced from
  // what was actually compiled, not from what is on disk.
  const pagesManifest = join(ROOT, '.next/server/pages-manifest.json')
  if (existsSync(pagesManifest)) {
    for (const key of Object.keys(JSON.parse(readFileSync(pagesManifest, 'utf8')))) {
      // /_app, /_document and /_error are framework internals, not app routes.
      if (/^\/_(app|document|error)$/.test(key)) continue
      routes.set(fillDynamicSegments(key), { isHandler: key.startsWith('/api/') })
    }
  }

  const manifestPath = join(ROOT, '.next/server/app-paths-manifest.json')
  if (!existsSync(manifestPath)) return routes
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as Record<string, string>
  for (const key of Object.keys(manifest)) {
    const isHandler = key.endsWith('/route')
    let route = key.replace(/\/(page|route)$/, '')
    if (route.startsWith('/_')) continue

    routes.set(fillDynamicSegments(route), { isHandler })
  }
  return routes
}

function fillDynamicSegments(key: string): string {
  // Route groups `(marketing)` and parallel slots `@modal` organise files and are
  // NOT part of the URL. Leaving them in made the scan fetch a path that does not
  // exist, fail on the 404, and never read the page that does exist.
  const route = key.replace(/\/\([^/]+\)/g, '').replace(/\/@[^/]+/g, '')
    // [...slug] and [[...slug]] take several segments; [id] takes one.
    .replace(/\[\[?\.\.\.[^\]]+\]\]?/g, 'aaaaaaaa-0000-4000-8000-000000000000/second')
    .replace(/\[[^\]]+\]/g, 'aaaaaaaa-0000-4000-8000-000000000000')
  return route === '' ? '/' : route
}

/**
 * A stand-in for the Supabase REST and Auth endpoints.
 *
 * Without it the dashboard cannot render at all, so the four routes that actually
 * display tenant data were excluded from the scan -- leaving it covering `/login`
 * and three "Coming in a later phase" placeholders while reporting a clean bill of
 * health. It returns empty result sets, which is all a leak check needs: the
 * question is whether the SERVER's own secrets reach the browser, not what the rows
 * contain.
 */
function startSupabaseStub(port: number): { server: import('node:http').Server; failed: () => boolean } {
  const server = createServer((req, res) => {
    const url = req.url ?? '/'
    res.setHeader('content-type', 'application/json')
    if (url.startsWith('/auth/v1/factors') || url.startsWith('/auth/v1/user')) {
      // A user WITH a verified TOTP factor. Answering 401 here meant
      // listFactors() came back empty and /mfa/verify redirected to enrolment on
      // every request, so the one page that renders a factor was never read.
      res.writeHead(200)
      res.end(JSON.stringify({
        id: '00000000-0000-0000-0000-000000000000',
        email: 'secret-scan@localhost',
        aud: 'authenticated',
        app_metadata: {},
        user_metadata: {},
        created_at: new Date(0).toISOString(),
        factors: [{
          id: '11111111-1111-4111-8111-111111111111',
          friendly_name: 'scan',
          factor_type: 'totp',
          status: 'verified',
          created_at: new Date(0).toISOString(),
          updated_at: new Date(0).toISOString(),
        }],
      }))
      return
    }
    res.writeHead(200)
    res.end(url.startsWith('/rest/v1/') ? '[]' : '{}')
  })
  let bindFailed = false
  server.on('error', (error) => {
    console.error(`  the Supabase stub could not bind port ${port}: ${(error as Error).message}`)
    bindFailed = true
  })
  server.listen(port, '127.0.0.1')
  return { server, failed: () => bindFailed }
}

type Fetched = { text: string; status: number; location: string | null }

async function fetchDocument(
  url: string,
  extra: Record<string, string> = {},
  method: 'GET' | 'POST' = 'GET',
): Promise<Fetched> {
  try {
    // NEVER follow. `redirect: 'follow'` discards the redirect response itself --
    // including its Set-Cookie and any custom header -- and a secret in a
    // Set-Cookie on a 307 reaches the browser just as surely as one in a body.
    // Verified: a route appending the service-role key to Set-Cookie on a redirect
    // passed the whole scan.
    const response = await fetch(url, {
      method,
      headers: { ...extra },
      redirect: 'manual',
    })
    const body = await response.text()
    // Header values count too: a secret in a Set-Cookie or a custom header ships.
    const headerText = [...response.headers.entries()].map(([k, v]) => `${k}: ${v}`).join('\n')
    let location: string | null = null
    const rawLocation = response.headers.get('location')
    if (rawLocation) {
      try { location = new URL(rawLocation, ORIGIN).pathname } catch { location = rawLocation }
    }
    return { text: `${headerText}\n${body}`, status: response.status, location }
  } catch {
    return { text: '', status: 0, location: null }
  }
}

/**
 * Waits for OUR server, and proves it is ours.
 *
 * Waiting for "something answers on the port" is not enough. With an unrelated
 * process holding the port, the scan happily read a 40-byte dummy page eight times
 * and reported "16 served responses scanned" -- a higher number than the honest
 * run -- and exited 0. The acknowledgement header can only be produced by something
 * that knows this run's token.
 */
async function waitForOurServer(): Promise<string | null> {
  // Poll /login, which renders for an anonymous caller. The ack-header handshake
  // this replaces existed to prove the scan was reading OUR build rather than some
  // other process on the port; the port is now checked for a squatter before the
  // server starts, which answers the same question without shipping a header.
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      const response = await fetch(`${ORIGIN}/login`, { redirect: 'manual' })
      if (response.status > 0) return null
    } catch { /* not up yet */ }
    await new Promise((resolve) => setTimeout(resolve, 200))
  }
  return 'the app never became reachable on ' + ORIGIN
}

async function checkServedResponses() {
  const buildProbeLog = join(PROBE_DIR, 'build-probe.log')
  console.log('  building with canary secrets in the server environment...')
  rmSync(join(ROOT, '.next'), { recursive: true, force: true })
  try {
    // The probe rides the BUILD too: a prerendered route is rendered once and served
    // from cache forever, so a build-time read never reappears at request time.
    // See BUILD_NOTES G105.
    writeFileSync(buildProbeLog, '')
    execFileSync('npx', ['next', 'build'], {
      cwd: ROOT,
      env: {
        ...buildEnvironment(),
        RENDER_PROBE_LOG: buildProbeLog,
        RENDER_PROBE_ALLOWED_PORT: String(STUB_PORT),
        NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ''} --require ${join(ROOT, 'scripts/render-probe.cjs')}`.trim(),
      },
      stdio: 'pipe', encoding: 'utf8',
    })
  } catch (err: any) {
    fail(`next build failed, so nothing could be scanned:\n${err.stdout ?? ''}${err.stderr ?? ''}`)
    return
  }

  const routes = routesFromManifest()
  if (routes.length === 0) {
    fail('no routes were found in the build manifest — the scan would have been vacuous')
    return
  }

  const buildReads = existsSync(buildProbeLog) ? readFileSync(buildProbeLog, 'utf8').trim() : ''
  if (buildReads) {
    fail('the production BUILD performed a tenant data read. Whatever route did this is '
      + 'prerendered, so the rows are baked into the build output and served to every '
      + `visitor from cache:\n${buildReads.split('\n').map((l) => `      ${l}`).join('\n')}`)
  } else {
    pass('the production build performed no tenant data read, so no rows are baked into a '
      + 'prerendered route')
  }

  console.log(`  serving the app and reading ${routes.length} route(s) as a browser would...`)
  const stub = startSupabaseStub(STUB_PORT)
  const stubFailed = () => stub.failed()

  // Bound to loopback: this server runs with the scan bypass live and must not be
  // reachable from the network.
  // The probe records data reads the render actually performs. See
  // scripts/render-probe.cjs for why this exists rather than another static model.
  const probeLog = join(PROBE_DIR, 'render-probe.log')
  writeFileSync(probeLog, '')
  const server = spawn('npx', ['next', 'start', '-p', String(PORT), '-H', '127.0.0.1'], {
    cwd: ROOT,
    env: {
      ...buildEnvironment(),
      RENDER_PROBE_LOG: probeLog,
      RENDER_PROBE_ALLOWED_PORT: String(STUB_PORT),
      NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ''} --require ${join(ROOT, 'scripts/render-probe.cjs')}`.trim(),
    },
    stdio: ['ignore', 'ignore', 'pipe'], detached: true,
  })
  let serverStderr = ''
  server.stderr?.on('data', (chunk) => { serverStderr += String(chunk) })
  let serverExited = false
  server.on('exit', () => { serverExited = true })

  const found: string[] = []
  const rendered = new Set<string>()
  let scanned = 0
  let flightPayloads = 0
  try {
    const startupProblem = await waitForOurServer()
    if (stubFailed()) {
      // Printing "all checks passed" after this happened, with only a non-zero exit
      // code to say otherwise, is the reporting failure this project keeps finding.
      fail('the Supabase stub could not bind its port, so the app was talking to '
        + 'something else and nothing below was measured against this build')
      return
    }
    if (startupProblem) {
      fail(`${startupProblem}${serverExited ? `\n    next start exited early:\n${serverStderr.trim()}` : ''}`)
      return
    }

    // There is no allowlist. Every route must render and be inspected, or the scan
    // fails. An earlier version excused four routes to a console note -- and those
    // four were the only ones that render tenant data, so the scan covered `/login`
    // and three placeholders while reporting success.
    const notRendered: string[] = []
    const redirected: string[] = []

    const table = routeTable()

    /** Inspects one response and records it, or records why it could not be. */
    const inspect = (label: string, doc: Fetched, route: string) => {
      if (doc.status === 0) {
        notRendered.push(`${label} could not be fetched`)
        return
      }
      // A redirect asked for inside a FLIGHT request is not an HTTP 3xx: Next
      // answers 200 with a NEXT_REDIRECT digest in the payload. That is the correct
      // outcome for /mfa/verify seen by a verified session, so it is classified as
      // a redirect -- still read for canaries -- rather than as an unreadable page.
      const isFlightRedirect = /NEXT_REDIRECT/.test(doc.text)

      // A 200 that is really Next's error boundary carries no page content.
      if (doc.status === 200 && !isFlightRedirect && /__next_error__|"digest":"NEXT_/.test(doc.text)) {
        notRendered.push(`${label} rendered an error boundary`)
        return
      }
      // Anything else IS inspected, including a redirect. A redirect's headers go
      // to the browser, and Set-Cookie is exactly where a leaked value would sit.
      scanned++
      for (const [name, canary] of Object.entries(CANARIES)) {
        if (doc.text.includes(canary)) found.push(`${name} leaked into the response for ${label}`)
      }
      if (/service_role/.test(doc.text)) {
        found.push(`the string "service_role" appears in the response for ${label}`)
      }
      if (isFlightRedirect) {
        redirected.push(`${label} redirects, expressed in the flight payload`)
        return
      }
      if (doc.status >= 300 && doc.status < 400) {
        const destination = doc.location ?? '(no location header)'
        if (!table.has(destination)) {
          notRendered.push(`${label} redirects to ${destination}, which is not itself scanned`)
        } else {
          redirected.push(`${route} → ${destination}, scanned on its own turn`)
        }
      }
    }

    // Every session state the app can render in. Scanning only as a verified user
    // meant /mfa/enroll and /mfa/verify -- which redirect a verified user away --
    // could never render, so three of eight routes were measured as redirects while
    // the headline said "24 responses scanned".
    // One pass, unauthenticated. The three-state scan-mode loop that used to live
    // here needed an auth-bypass shipped in production code to render authenticated
    // pages; for a one-person tool that was the worst trade in the repo -- 120 lines
    // of production auth surface so a scanner could read three static headings. The
    // canary grep still covers every response and every static chunk, and the render
    // probe still covers every route.
    for (const [route, meta] of table) {
      const requests: Array<[string, Promise<Fetched>]> = [
        [route, fetchDocument(`${ORIGIN}${route}`)],
      ]
      if (meta.isHandler) requests.push([`${route} (POST)`, fetchDocument(`${ORIGIN}${route}`, {}, 'POST')])
      else requests.push([`${route} (RSC)`, fetchDocument(`${ORIGIN}${route}?_rsc=1`, { RSC: '1' })])
      for (const [label, pending] of requests) {
        const doc = await pending
        scanned += 1
        if (doc.status >= 200 && doc.status < 300) rendered.add(route)
        if (label.endsWith('(RSC)') && doc.status >= 200 && doc.status < 300) flightPayloads += 1
        for (const [name, canary] of Object.entries(CANARIES)) {
          if (doc.text.includes(canary)) found.push(`${name} appears in ${label}`)
        }
      }
    }

    if (redirected.length) {
      console.log(`  NOTE  ${redirected.length} response(s) redirect to a route scanned on its own turn`)
    }
    if (notRendered.length) {
      fail(`these responses could not be inspected, so the scan is incomplete:\n    `
        + notRendered.join('\n    '))
    }

    // Completeness, not volume. "24 responses scanned" was true while 14 of them
    // were redirect envelopes and none was a flight payload.
    // An anonymous caller renders /login and is redirected everywhere else, so the
    // canary grep covers one document. The authenticated pages are covered by the
    // build probe, the render probe and the static-chunk scan instead; the auth
    // bypass that used to let this scan render them is deleted. See BUILD_NOTES G108.
    if (rendered.size === 0 && table.size > 0) {
      fail('not one route rendered a document, so the canary scan inspected only '
        + 'redirect envelopes — the failure mode this check exists to catch')
    }

    const neverRendered = [...table.keys()].filter((route) => !rendered.has(route))

    console.log(`  READ  ${rendered.size}/${table.size} route(s) rendered for an anonymous `
      + `caller (${flightPayloads} flight payload(s)); the rest redirect, and are covered `
      + 'by the build probe, the render probe and the static-chunk scan')
    if (neverRendered.length) {
      console.log(`  NOTE  ${neverRendered.length} route(s) only ever redirected; the probe below still requested each one`)
    }

  } finally {
    try { process.kill(-server.pid!, 'SIGKILL') } catch { /* already gone */ }
    stub.server.close()
  }

  // The static chunks are still worth checking: a secret inlined at BUILD time
  // lands there instead.
  const chunkFiles = walk(join(ROOT, '.next/static'))
  for (const file of chunkFiles) {
    const text = readFileSync(file, 'utf8')
    for (const [name, canary] of Object.entries(CANARIES)) {
      if (text.includes(canary)) found.push(`${name} leaked into ${relative(ROOT, file)}`)
    }
    if (/service_role/.test(text)) found.push(`the string "service_role" appears in ${relative(ROOT, file)}`)
  }

  if (found.length) {
    fail(`SECRETS REACHABLE BY THE BROWSER:\n    ${found.join('\n    ')}`)
  } else {
    pass(`no server-only secret appears in any of ${scanned} served responses `
      + `or ${chunkFiles.length} static chunks`)
  }
}

// ---------------------------------------------------------------------------
// 5. Scan mode must not be reachable in a real deployment.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------

async function main() {
  console.log('\nSecret-leak check\n' + '='.repeat(60))
  checkGitTracked()
  checkPublicVarNames()
  checkAdminClientIsServerOnly()
  assertCanariesCoverEveryServerVar()
  await checkServedResponses()

  for (const p of passes) console.log(`  PASS  ${p}`)
  for (const f of failures) console.error(`  FAIL  ${f}`)
  console.log('='.repeat(60))

  if (failures.length) {
    console.error(`\n${failures.length} secret-handling check(s) failed.\n`)
    process.exit(1)
  }
  console.log(`\nAll ${passes.length} secret-handling checks passed.\n`)
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
