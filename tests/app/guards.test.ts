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

/**
 * The whole project, not just app/ and lib/.
 *
 * A `'use server'` module is legal anywhere under the project root -- `components/`,
 * `server/`, `src/` are all idiomatic -- and walking two directories meant an
 * unguarded action a directory over was invisible to every check in this file.
 */
const SKIP_DIRECTORIES = new Set(['node_modules', '.next', '.git', 'tests', 'supabase', 'scripts'])

function walkProject(dir = '.', out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRECTORIES.has(entry)) continue
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) walkProject(full, out)
    else out.push(full)
  }
  return out
}

const appFiles = walkProject()

/**
 * A 'use server' module can be .ts OR .tsx -- an actions file colocated with a
 * component, or inline actions inside one, are both idiomatic Next. Filtering to
 * .ts alone made every .tsx action invisible to this whole file.
 */
const actionFiles = appFiles.filter(
  (f) => /\.tsx?$/.test(f) && /['"]use server['"]/.test(readFileSync(f, 'utf8')),
)
// Every file convention Next will render as, or on behalf of, a route. A guard on
// page.tsx alone leaves default.tsx (parallel-route slots), opengraph-image.tsx and
// the metadata routes rendering with nothing but the proxy in front of them.
const pageFiles = appFiles.filter((f) => /\/(page|default)\.tsx$/.test(f))
const layoutFiles = appFiles.filter((f) => /\/(layout|template)\.tsx$/.test(f))
const metadataRoutes = appFiles.filter(
  (f) => /\/(opengraph-image|twitter-image|icon|apple-icon|sitemap|robots|not-found)\.tsx?$/.test(f),
)
const routeHandlers = appFiles.filter((f) => /\/route\.tsx?$/.test(f))

/** Source with comments removed, so a commented-out guard cannot satisfy a match. */
function code(file: string): string {
  return readFileSync(file, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1')
}

/**
 * Every exported binding in a 'use server' file is a callable server action.
 *
 * All three declaration forms are matched. An earlier version recognised only
 * `export async function`, so `export const x = async () => {}` -- an ordinary
 * server action -- was invisible to every check in this file, which is precisely
 * the case it exists to catch.
 */
const DECLARATION_FORMS = [
  /export\s+async\s+function\s+(\w+)/g,          // export async function foo()
  /export\s+(?:const|let|var)\s+(\w+)\s*=\s*async/g, // export const foo = async ()
  /export\s+default\s+async\s+function\s+(\w+)/g, // export default async function foo()
]

function exportedActions(file: string): string[] {
  const source = code(file)
  const names = new Set<string>()
  for (const pattern of DECLARATION_FORMS) {
    for (const match of source.matchAll(pattern)) names.add(match[1]!)
  }
  return [...names]
}

/** Every exported binding at all, however it is declared. Used to prove the
 *  matchers above did not silently miss one. */
function everyExportedBinding(file: string): string[] {
  const source = code(file)
  const names = new Set<string>()
  for (const m of source.matchAll(/export\s+(?:async\s+)?(?:function|const|let|var)\s+(\w+)/g)) {
    names.add(m[1]!)
  }
  for (const m of source.matchAll(/export\s*\{([^}]*)\}/g)) {
    for (const part of m[1]!.split(',')) {
      const name = part.trim().split(/\s+as\s+/)[0]?.trim()
      if (name) names.add(name)
    }
  }
  return [...names]
}

/**
 * The body of one exported action, ending at the next export OR at a
 * non-exported declaration. Stopping only at the next `export` let the last
 * action in a file absorb trailing private helpers, so an assertCsrf() in a
 * helper below satisfied the check for an action that never called it.
 */
function bodyOf(file: string, name: string): string {
  const source = code(file)
  const start = source.search(new RegExp(`export\\s+(?:default\\s+)?(?:async\\s+function\\s+${name}\\b|(?:const|let|var)\\s+${name}\\b)`))
  if (start === -1) throw new Error(`could not locate ${name} in ${file}`)
  const rest = source.slice(start + 1)
  const nextBoundary = rest.search(/\n(?:export\s|(?:async\s+)?function\s|const\s|let\s|var\s)/)
  return rest.slice(0, nextBoundary === -1 ? undefined : nextBoundary)
}

test.each(appFiles.filter((f) => /\.tsx?$/.test(f)).map((f) => relative(process.cwd(), f)))(
  '%s — has no anonymous default export, which would hide anything declared inside it',
  (file) => {
    // `export default async function () {` binds no name, so both the
    // "recognised actions" and "all exports" matchers return nothing and the
    // equality guard below is satisfied by two empty lists. An inline
    // `'use server'` action inside such a component is then never examined.
    expect(code(join(process.cwd(), file)), `${file} default-exports an anonymous function`)
      .not.toMatch(/export\s+default\s+(async\s+)?function\s*\(/)
  })

test.each(appFiles.filter((f) => /\.tsx?$/.test(f)).map((f) => relative(process.cwd(), f)))(
  '%s — any inline server action is guarded where it is declared',
  (file) => {
    // An action can be declared inside a component body with its own 'use server'
    // directive. It is a real, callable entry point and belongs to no exported
    // binding, so it is checked here by its enclosing declaration.
    const source = code(join(process.cwd(), file))
    const inlineActions = [...source.matchAll(
      /(?:async\s+function\s+(\w+)|const\s+(\w+)\s*=\s*async)[^{]*\{\s*['"]use server['"]/g,
    )]
    for (const match of inlineActions) {
      const name = match[1] ?? match[2]
      const body = source.slice(match.index!, source.indexOf('\n  }', match.index!) + 4)
      expect(body, `inline action ${name} in ${file} does not check CSRF`).toMatch(/assertCsrf\(/)
      expect(body, `inline action ${name} in ${file} does not establish a session`)
        .toMatch(/require(MfaSession|SignedInUser)OrThrow\(/)
    }
  })

test('there is at least one server action to check, so this test cannot pass vacuously', () => {
  expect(actionFiles.length).toBeGreaterThan(0)
  expect(actionFiles.flatMap(exportedActions).length).toBeGreaterThan(0)
})

test.each(actionFiles.map((f) => relative(process.cwd(), f)))(
  '%s — does not re-export actions with `export *`, which would hide them entirely',
  (file) => {
    // `export *` makes an action callable while appearing in neither the recognised
    // set nor the all-exports set, so the equality check below passes and the action
    // is never examined. There is no way to follow it with a regex, so it is banned.
    expect(code(join(process.cwd(), file)), `${file} uses \`export *\`; name each action explicitly`)
      .not.toMatch(/export\s+\*/)
  })

test.each(actionFiles.map((f) => relative(process.cwd(), f)))(
  '%s — every exported binding is recognised as an action, so none can slip past unchecked',
  (file) => {
    // The guard against this whole file quietly under-reporting. If someone
    // declares an action in a form the matchers do not know, this fails loudly
    // instead of the action simply never being checked.
    const full = join(process.cwd(), file)
    const recognised = exportedActions(full).sort()
    const allExports = everyExportedBinding(full).sort()
    expect(recognised, `unrecognised exports in ${file}: ${allExports.filter((n) => !recognised.includes(n)).join(', ')}`)
      .toEqual(allExports)
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

  // requireSignedInUserOrThrow accepts a PASSWORD-ONLY (aal1) session. That is
  // necessary inside the MFA flow, which by definition runs before aal2 exists, and
  // for signing out -- a user who cannot complete MFA must still be able to leave.
  // Anywhere else it is not a guard at all, so it is allowed by PATH, not by habit.
  const MAY_ACCEPT_AAL1 = (file: string, name: string) =>
    file.startsWith('app/mfa/') || name === 'signOutAction'

  test.each(everyAction)('%s → %s() independently establishes the session', (file, name) => {
    if (CREATES_THE_SESSION.has(name)) return
    const body = bodyOf(join(process.cwd(), file), name)
    // Next.js routes server actions as POSTs to the page they live on, so the
    // proxy's matcher cannot be relied on to have covered them.
    if (MAY_ACCEPT_AAL1(file, name)) {
      expect(body, `${name} relies on the proxy alone`).toMatch(
        /require(MfaSession|SignedInUser)OrThrow\(/)
    } else {
      expect(body, `${name} accepts a password-only session; it needs requireMfaSessionOrThrow`)
        .toMatch(/requireMfaSessionOrThrow\(/)
    }
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
      expect(source).toMatch(/resolveSessionState\(/)
      return
    }

    expect(source, `${file} renders without requireMfaSession()`).toMatch(/requireMfaSession\(/)
  })
})

describe('every route handler', () => {
  const MUTATING = ['POST', 'PUT', 'PATCH', 'DELETE']

  test('there are none, or each one is guarded', () => {
    // Route handlers are a separate entry point from server actions and were
    // previously checked for nothing but exchangeCodeForSession. An unguarded
    // GET /dashboard/export returning `select * from businesses` would have passed.
    for (const file of routeHandlers) {
      const relPath = relative(process.cwd(), file)
      const source = code(file)
      // Both declaration forms. `export const POST = async () => {}` is ordinary and
      // matching only `export async function POST` meant the CSRF requirement below
      // simply never applied to it.
      const methodPattern =
        /export\s+(?:async\s+function\s+|const\s+)(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/g
      const methods = [...source.matchAll(methodPattern)].map((m) => ({
        name: m[1]!,
        // Each method is checked on its OWN body: a file-wide match let a guarded
        // GET vouch for an unguarded POST sitting beside it.
        body: (() => {
          const from = m.index!
          const rest = source.slice(from + 1)
          const next = rest.search(methodPattern)
          return rest.slice(0, next === -1 ? undefined : next)
        })(),
      }))

      expect(methods.length, `${relPath} exports no recognised HTTP method`).toBeGreaterThan(0)

      for (const method of methods) {
        expect(method.body, `${relPath} ${method.name} does not establish a session`)
          .toMatch(/requireMfaSession(OrThrow)?\(/)
        if (MUTATING.includes(method.name)) {
          expect(method.body, `${relPath} ${method.name} mutates without a CSRF check`)
            .toMatch(/assertCsrf\(/)
        }
      }
    }
  })
})

test('no metadata route renders tenant data without establishing a session', () => {
  // opengraph-image.tsx and friends are real routes, and the image ones are exactly
  // the sort of response a CDN will cache.
  for (const file of metadataRoutes) {
    const source = code(file)
    if (/\.from\(|\.rpc\(/.test(source)) {
      expect(source, `${relative(process.cwd(), file)} queries the database without a session guard`)
        .toMatch(/requireMfaSession\(/)
    }
  }
})

test('no layout or template renders tenant data without establishing a session', () => {
  // A layout wraps every page beneath it and can query just as freely.
  for (const file of layoutFiles) {
    const source = code(file)
    if (/\.from\(|\.rpc\(/.test(source)) {
      expect(source, `${relative(process.cwd(), file)} queries the database without a session guard`)
        .toMatch(/requireMfaSession\(/)
    }
  }
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
