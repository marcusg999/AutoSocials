/**
 * CLASS TEST: every server action is CSRF-protected and session-guarded, and every
 * page establishes a session before it renders.
 *
 * This is deliberately a structural check over the whole app rather than a test of
 * particular routes. The failure mode it guards against is not "this action is
 * wrong" but "someone added a new action next year and forgot" — which no
 * hand-written per-route test can catch.
 */
import { describe, expect, test } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) walk(full, out)
    else out.push(full)
  }
  return out
}

const appFiles = walk('app')
const actionFiles = appFiles.filter((f) => f.endsWith('.ts') && /['"]use server['"]/.test(readFileSync(f, 'utf8')))
const pageFiles = appFiles.filter((f) => /\/page\.tsx$/.test(f))
const routeHandlers = appFiles.filter((f) => /\/route\.ts$/.test(f))

/** Every exported async function in a 'use server' file is a callable server action. */
function exportedActions(file: string): string[] {
  const source = readFileSync(file, 'utf8')
  return [...source.matchAll(/export\s+async\s+function\s+(\w+)/g)].map((m) => m[1]!)
}

/** The body of one exported function, up to the next export. */
function bodyOf(file: string, name: string): string {
  const source = readFileSync(file, 'utf8')
  const start = source.indexOf(`export async function ${name}`)
  const next = source.indexOf('export async function ', start + 1)
  return source.slice(start, next === -1 ? undefined : next)
}

test('there is at least one server action to check, so this test cannot pass vacuously', () => {
  expect(actionFiles.length).toBeGreaterThan(0)
  expect(actionFiles.flatMap(exportedActions).length).toBeGreaterThan(0)
})

describe('every server action', () => {
  const everyAction = actionFiles.flatMap((file) =>
    exportedActions(file).map((name) => [relative(process.cwd(), file), name] as const))

  test.each(everyAction)('%s → %s() checks CSRF first', (file, name) => {
    const body = bodyOf(join(process.cwd(), file), name)
    expect(body, `${name} does not call assertCsrf`).toMatch(/await assertCsrf\(/)

    // CSRF must be the first thing, before any session lookup or mutation.
    const csrfAt = body.indexOf('assertCsrf')
    const otherAwait = body.search(/await (?!assertCsrf)/)
    if (otherAwait !== -1) {
      expect(csrfAt, `${name} does something before checking CSRF`).toBeLessThan(otherAwait)
    }
  })

  // The only action that may not require a session is the one that creates it.
  const CREATES_THE_SESSION = new Set(['signInAction'])

  test.each(everyAction)('%s → %s() independently establishes the session', (file, name) => {
    if (CREATES_THE_SESSION.has(name)) return
    const body = bodyOf(join(process.cwd(), file), name)
    // Next.js routes server actions as POSTs to the page they live on, so the
    // proxy's matcher cannot be relied on to have covered them.
    expect(body, `${name} relies on the proxy alone`).toMatch(
      /require(MfaSession|SignedInUser)OrThrow\(/)
  })
})

describe('every page', () => {
  // Pages that legitimately render before a full aal2 session exists. Each is
  // listed with the reason it is safe, and each is checked for what it MUST do.
  const PRE_MFA_PAGES = ['app/mfa/enroll/page.tsx', 'app/mfa/verify/page.tsx']

  // Pages that render no data at all, so there is nothing for a session to protect.
  // Anything added here must be genuinely dataless — a form or a redirect.
  const RENDERS_NO_DATA = ['app/login/page.tsx', 'app/page.tsx']

  test('there is at least one page to check', () => {
    expect(pageFiles.length).toBeGreaterThan(0)
  })

  test.each(pageFiles.map((f) => relative(process.cwd(), f)))('%s establishes a session before rendering', (file) => {
    const source = readFileSync(join(process.cwd(), file), 'utf8')

    if (RENDERS_NO_DATA.includes(file)) {
      // Hold them to that promise: no database read may appear on these pages.
      expect(source, `${file} is listed as dataless but queries the database`)
        .not.toMatch(/\.from\(|\.rpc\(|createSupabase/)
      return
    }

    if (PRE_MFA_PAGES.includes(file)) {
      // These run before aal2 exists by necessity, but must still prove the
      // password step happened and must redirect a verified user away.
      expect(source).toMatch(/resolveSessionState\(|requireSignedInUser\(/)
      return
    }

    expect(source, `${file} renders without requireMfaSession()`).toMatch(/requireMfaSession\(/)
  })
})

test('no route handler exchanges a query parameter for a session', () => {
  // Phase 1 signs in with email and password only. A code-exchange endpoint must
  // sit outside the auth guards by nature, so it is not shipped until a phase
  // actually needs OAuth — and then it needs a state parameter bound to a cookie.
  for (const file of routeHandlers) {
    const source = readFileSync(file, 'utf8')
    expect(source, `${file} exchanges a code for a session`).not.toMatch(/exchangeCodeForSession/)
  }
})

test('the service-role client is only reachable from server-only modules', () => {
  const importers = walk('lib').concat(walk('app'))
    .filter((f) => /\.(ts|tsx)$/.test(f))
    .filter((f) => /supabase\/admin/.test(readFileSync(f, 'utf8')))
    .filter((f) => !f.endsWith('lib/supabase/admin.ts'))

  for (const file of importers) {
    const source = readFileSync(file, 'utf8')
    expect(source, `${file} imports the service-role client without 'server-only'`)
      .toMatch(/import ['"]server-only['"]/)
  }
})
