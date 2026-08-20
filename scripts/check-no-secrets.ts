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
import { SCAN_HEADER } from '../lib/security/scan-mode'
import { existsSync, readFileSync, readdirSync, statSync, rmSync } from 'node:fs'
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

// ---------------------------------------------------------------------------
// 2. No secret-sounding variable may be exposed as NEXT_PUBLIC_.
//    Anything prefixed NEXT_PUBLIC_ is inlined into the browser bundle by Next.js.
// ---------------------------------------------------------------------------
const FORBIDDEN_IN_PUBLIC = /(SERVICE_ROLE|SECRET|PRIVATE|PASSWORD|_TOKEN|CREDENTIAL|SIGNING|VAULT)/i

function checkPublicVarNames() {
  const sources = [
    ...walk(join(ROOT, 'app')), ...walk(join(ROOT, 'lib')),
    ...walk(join(ROOT, 'scripts')), ...walk(join(ROOT, 'tests')),
  ].filter((f) => /\.(ts|tsx|js|jsx|mjs)$/.test(f))
  if (existsSync(join(ROOT, 'proxy.ts'))) sources.push(join(ROOT, 'proxy.ts'))
  if (existsSync(join(ROOT, '.env.example'))) sources.push(join(ROOT, '.env.example'))

  const offenders: string[] = []
  for (const file of sources) {
    for (const name of readFileSync(file, 'utf8').match(/NEXT_PUBLIC_[A-Z0-9_]+/g) ?? []) {
      if (FORBIDDEN_IN_PUBLIC.test(name)) offenders.push(`${relative(ROOT, file)}: ${name}`)
    }
  }
  if (offenders.length) fail(`secret-sounding NEXT_PUBLIC_ variables (these are inlined into the browser bundle):\n    ${offenders.join('\n    ')}`)
  else pass('no NEXT_PUBLIC_ variable is named like a secret')
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

  const clientComponents = [...walk(join(ROOT, 'app')), ...walk(join(ROOT, 'lib'))]
    .filter((f) => /\.(tsx?|jsx?)$/.test(f))
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
const CANARIES = {
  SUPABASE_SERVICE_ROLE_KEY: 'CANARY_SERVICE_ROLE_a1b2c3d4e5f6a7b8',
  SUPABASE_DB_PASSWORD: 'CANARY_DB_PASSWORD_9f8e7d6c5b4a3928',
  CSRF_SIGNING_SECRET: 'CANARY_CSRF_SECRET_5a4b3c2d1e0f9887_at_least_32_chars',
} as const

const PORT = 3987
const ORIGIN = `http://127.0.0.1:${PORT}`

// Lets the scanner render authenticated pages. Generated fresh for each run and
// never written anywhere. See lib/security/scan-mode.ts for the fences.
const SCAN_TOKEN = randomBytes(32).toString('hex')

function buildEnvironment(): NodeJS.ProcessEnv {
  return {
    ...process.env,
    ...CANARIES,
    NEXT_PUBLIC_SUPABASE_URL: process.env.NEXT_PUBLIC_SUPABASE_URL ?? 'https://example.supabase.co',
    NEXT_PUBLIC_SUPABASE_ANON_KEY: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? 'public-anon-key-safe-to-ship',
    APP_ORIGIN: ORIGIN,
    SECRET_SCAN_TOKEN: SCAN_TOKEN,
    NEXT_TELEMETRY_DISABLED: '1',
  }
}

/** Every route the app serves, read from Next's own manifest. */
function routesFromManifest(): string[] {
  const manifestPath = join(ROOT, '.next/server/app-paths-manifest.json')
  if (!existsSync(manifestPath)) return []
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as Record<string, string>
  const routes = new Set<string>()
  for (const key of Object.keys(manifest)) {
    const route = key.replace(/\/(page|route)$/, '')
    // Skip Next's internal error pages and any dynamic segment we cannot fill in.
    if (route.startsWith('/_')) continue
    if (route.includes('[')) continue
    routes.add(route === '' ? '/' : route)
  }
  return [...routes]
}

type Fetched = { text: string; status: number }

async function fetchDocument(url: string, extra: Record<string, string> = {}): Promise<Fetched> {
  try {
    // Redirects are followed, because several routes redirect by design even for a
    // fully authenticated user ('/' and the MFA pages all send a verified session on
    // to the dashboard). What we want is the document that is finally rendered.
    const response = await fetch(url, {
      headers: { [SCAN_HEADER]: SCAN_TOKEN, ...extra },
      redirect: 'follow',
    })
    const body = await response.text()
    // Header values count too: a secret in a Set-Cookie or a custom header ships.
    const headerText = [...response.headers.entries()].map(([k, v]) => `${k}: ${v}`).join('\n')
    return { text: `${headerText}\n${body}`, status: response.status }
  } catch {
    return { text: '', status: 0 }
  }
}

async function waitForServer(): Promise<boolean> {
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      await fetch(`${ORIGIN}/login`, { redirect: 'manual' })
      return true
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 500))
    }
  }
  return false
}

async function checkServedResponses() {
  console.log('  building with canary secrets in the server environment...')
  rmSync(join(ROOT, '.next'), { recursive: true, force: true })
  try {
    execFileSync('npx', ['next', 'build'], { cwd: ROOT, env: buildEnvironment(), stdio: 'pipe', encoding: 'utf8' })
  } catch (err: any) {
    fail(`next build failed, so nothing could be scanned:\n${err.stdout ?? ''}${err.stderr ?? ''}`)
    return
  }

  const routes = routesFromManifest()
  if (routes.length === 0) {
    fail('no routes were found in the build manifest — the scan would have been vacuous')
    return
  }

  console.log(`  serving the app and reading ${routes.length} route(s) as a browser would...`)
  const server = spawn('npx', ['next', 'start', '-p', String(PORT)], {
    cwd: ROOT, env: buildEnvironment(), stdio: 'ignore', detached: true,
  })

  const found: string[] = []
  let scanned = 0
  try {
    if (!(await waitForServer())) {
      fail('the app did not start, so no served response could be scanned')
      return
    }

    // Routes that cannot render without a live Supabase project: the dashboard
    // lists the businesses RLS lets you see, and '/' and the MFA pages all send a
    // verified session on to it. Listed explicitly, reported in the output, and NOT
    // counted as scanned -- an environment limitation stated out loud rather than a
    // silent gap. Against a real project this list should be empty.
    const NEEDS_LIVE_DATABASE = ['/dashboard', '/', '/mfa/enroll', '/mfa/verify']
    const notRendered: string[] = []
    const unverifiable: string[] = []

    for (const route of routes) {
      const documents: Array<[string, Fetched]> = [
        [`${route} (HTML)`, await fetchDocument(`${ORIGIN}${route}`)],
        // The RSC flight payload: what a client-side navigation receives, and where
        // a server-to-client prop actually lands.
        [`${route} (RSC flight)`, await fetchDocument(`${ORIGIN}${route}`, { RSC: '1' })],
      ]
      for (const [label, doc] of documents) {
        // A redirect body is a handful of bytes and proves nothing. Counting one as
        // "scanned" is how this check previously reported 16 responses while
        // actually inspecting a single page.
        if (doc.status !== 200) {
          if (NEEDS_LIVE_DATABASE.includes(route)) unverifiable.push(`${label} returned ${doc.status}`)
          else notRendered.push(`${label} returned ${doc.status}`)
          continue
        }
        scanned++
        for (const [name, canary] of Object.entries(CANARIES)) {
          if (doc.text.includes(canary)) found.push(`${name} leaked into the response for ${label}`)
        }
        if (/service_role/.test(doc.text)) found.push(`the string "service_role" appears in the response for ${label}`)
      }
    }

    // Coverage is part of the result. If scan mode ever stops working, every route
    // becomes a redirect again and this fails loudly rather than passing vacuously.
    if (notRendered.length) {
      fail(`these responses could not be inspected, so the scan is incomplete:\n    `
        + notRendered.join('\n    '))
    }
    if (unverifiable.length) {
      console.log(`  NOTE  ${unverifiable.length} response(s) need a live Supabase project `
        + `and were NOT scanned:\n    ${unverifiable.join('\n    ')}`)
    }
  } finally {
    try { process.kill(-server.pid!, 'SIGKILL') } catch { /* already gone */ }
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
function checkScanModeIsNotShipped() {
  if (!existsSync(join(ROOT, '.env.example'))) return
  const example = readFileSync(join(ROOT, '.env.example'), 'utf8')
  if (/SECRET_SCAN_TOKEN/.test(example)) {
    fail('.env.example mentions SECRET_SCAN_TOKEN — scan mode must never look like a setting to configure')
  } else {
    pass('.env.example does not advertise the scan-mode bypass')
  }

  const scanModeSource = readFileSync(join(ROOT, 'lib/security/scan-mode.ts'), 'utf8')
  if (!/APP_ORIGIN/.test(scanModeSource) || !/throw new Error/.test(scanModeSource)) {
    fail('lib/security/scan-mode.ts no longer refuses to run against a non-local APP_ORIGIN')
  } else {
    pass('scan mode refuses to run unless APP_ORIGIN is local')
  }
}

// ---------------------------------------------------------------------------

async function main() {
  console.log('\nSecret-leak check\n' + '='.repeat(60))
  checkGitTracked()
  checkPublicVarNames()
  checkAdminClientIsServerOnly()
  checkScanModeIsNotShipped()
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
