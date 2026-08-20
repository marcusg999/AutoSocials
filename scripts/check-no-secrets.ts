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
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync, rmSync } from 'node:fs'
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
      /(localhost|127\.0\.0\.1)/.test(value)
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
  if (leaks.length) fail(`client components reference the service-role client: ${leaks.map((f) => relative(ROOT, f)).join(', ')}`)
  else pass(`no 'use client' file references the service-role client (${clientComponents.length} client components scanned)`)
}

// ---------------------------------------------------------------------------
// 4. The real proof: build with canary secrets, then grep the client bundle.
// ---------------------------------------------------------------------------
const CANARIES = {
  SUPABASE_SERVICE_ROLE_KEY: 'CANARY_SERVICE_ROLE_a1b2c3d4e5f6a7b8',
  SUPABASE_DB_PASSWORD: 'CANARY_DB_PASSWORD_9f8e7d6c5b4a3928',
  CSRF_SIGNING_SECRET: 'CANARY_CSRF_SECRET_5a4b3c2d1e0f9887',
} as const

function checkBuiltBundle() {
  const buildEnv = {
    ...process.env,
    ...CANARIES,
    NEXT_PUBLIC_SUPABASE_URL: process.env.NEXT_PUBLIC_SUPABASE_URL ?? 'https://example.supabase.co',
    NEXT_PUBLIC_SUPABASE_ANON_KEY: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? 'public-anon-key-safe-to-ship',
    NEXT_TELEMETRY_DISABLED: '1',
  }

  console.log('  building with canary secrets in the server environment...')
  rmSync(join(ROOT, '.next'), { recursive: true, force: true })
  try {
    execFileSync('npx', ['next', 'build'], { cwd: ROOT, env: buildEnv, stdio: 'pipe', encoding: 'utf8' })
  } catch (err: any) {
    fail(`next build failed, so the bundle could not be scanned:\n${err.stdout ?? ''}${err.stderr ?? ''}`)
    return
  }

  // Everything the browser can download: the static chunk directory.
  const clientFiles = walk(join(ROOT, '.next/static'))
  if (!clientFiles.length) { fail('.next/static is empty — nothing was scanned'); return }

  const found: string[] = []
  for (const file of clientFiles) {
    const text = readFileSync(file, 'utf8')
    for (const [name, canary] of Object.entries(CANARIES)) {
      if (text.includes(canary)) found.push(`${name} leaked into ${relative(ROOT, file)}`)
    }
    // Also catch anything shaped like a Supabase service key or a JWT with the
    // service_role claim, in case a real key were ever hardcoded.
    if (/service_role/.test(text)) found.push(`the string "service_role" appears in ${relative(ROOT, file)}`)
  }

  if (found.length) fail(`SECRETS FOUND IN THE CLIENT BUNDLE:\n    ${found.join('\n    ')}`)
  else pass(`no server-only secret appears in any of ${clientFiles.length} client bundle files`)
}

// ---------------------------------------------------------------------------

console.log('\nSecret-leak check\n' + '='.repeat(60))
checkGitTracked()
checkPublicVarNames()
checkAdminClientIsServerOnly()
checkBuiltBundle()

for (const p of passes) console.log(`  PASS  ${p}`)
for (const f of failures) console.error(`  FAIL  ${f}`)
console.log('='.repeat(60))

if (failures.length) {
  console.error(`\n${failures.length} secret-handling check(s) failed.\n`)
  process.exit(1)
}
console.log(`\nAll ${passes.length} secret-handling checks passed.\n`)
