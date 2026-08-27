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
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'

import { closureSource, moduleClosure } from '../../scripts/module-closure'
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

// Every extension Next will compile as application code. Filtering on .ts/.tsx
// alone made `app/leak/page.jsx` and `app/api/leak/route.js` -- both real, routable,
// and unguarded -- invisible to every check in this file while the suite stayed green.
const SOURCE = /\.(m|c)?[jt]sx?$/

const appFiles = walkProject()

/**
 * A 'use server' module can be any extension Next compiles, so this uses SOURCE.
 *
 * It read /\.tsx?$/ while every other collector in this file read SOURCE. The same
 * action, byte for byte, was checked as danger.ts and completely unchecked as
 * danger.js -- registered in the server-reference manifest and callable -- and
 * tsconfig's `allowJs: false` meant typecheck could not see it either.
 */
const actionFiles = appFiles.filter(
  (f) => SOURCE.test(f) && /['"]use server['"]/.test(readFileSync(f, 'utf8')),
)
// Every file convention Next will render as, or on behalf of, a route. A guard on
// page.tsx alone leaves default.tsx (parallel-route slots), opengraph-image.tsx and
// the metadata routes rendering with nothing but the proxy in front of them.
const pageFiles = appFiles.filter((f) => /\/(page|default)\.(m|c)?[jt]sx?$/.test(f))
const layoutFiles = appFiles.filter((f) => /\/(layout|template)\.(m|c)?[jt]sx?$/.test(f))
const metadataRoutes = appFiles.filter(
  (f) => /\/(opengraph-image|twitter-image|icon|apple-icon|sitemap|robots|not-found)\.(m|c)?[jt]sx?$/.test(f),
)
const routeHandlers = appFiles.filter((f) => /\/route\.(m|c)?[jt]sx?$/.test(f))

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

/**
 * Everything Next compiles as application code: every file under app/, plus every
 * 'use server' module wherever it lives. Build configuration (next.config.ts,
 * vitest.config.mts) is neither served nor a place an action can hide, and an
 * anonymous default export is the normal way to write one.
 */
const COMPILED_AS_APP = appFiles.filter(
  (f) => SOURCE.test(f) && (f.startsWith('app/') || actionFiles.includes(f)),
)

test.each(COMPILED_AS_APP.map((f) => relative(process.cwd(), f)))(
  '%s — has no anonymous default export, which would hide anything declared inside it',
  (file) => {
    // `export default async function () {` binds no name, so both the
    // "recognised actions" and "all exports" matchers return nothing and the
    // equality guard below is satisfied by two empty lists. An inline
    // `'use server'` action inside such a component is then never examined.
    //
    // An arrow binds no name either, and banning only the `function` form left
    // `export default async (formData) => {}` -- a real, registered server action
    // doing a service-role delete with no CSRF and no session check -- invisible to
    // every check in this file. So the rule is that a default export must be a
    // NAMED declaration or a bare identifier, whatever syntax produced it.
    const source = code(join(process.cwd(), file))
    const defaultExport = source.match(/export\s+default\s+([\s\S]{0,40})/)
    if (!defaultExport) return
    const tail = defaultExport[1]!
    const isNamed =
      /^\s*(async\s+)?function\s+\w/.test(tail)   // export default function foo()
      || /^\s*(async\s+)?class\s+\w/.test(tail)   // export default class Foo
      || /^\s*\w+\s*(;|$|\n)/.test(tail)          // export default foo
    expect(isNamed, `${file} default-exports something anonymous (\`export default ${tail.trim().slice(0, 30)}\`); `
      + 'name it, or nothing in this file can see what it contains').toBe(true)
  })

test.each(appFiles.filter((f) => SOURCE.test(f)).map((f) => relative(process.cwd(), f)))(
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

describe('the enumeration this file performs is the complete one', () => {
  // Six review rounds have each found a file this suite models with a regex that is
  // narrower than the thing it claims to cover -- .tsx but not .jsx, page.tsx but
  // not default.tsx, `export async function` but not `export const`. These
  // assertions make the next narrowing fail loudly rather than be found by someone
  // walking an unguarded route.
  test('every routable file on disk is picked up by one of the collectors', () => {
    const ROUTE_CONVENTIONS =
      /\/(page|layout|template|default|route|loading|error|global-error|not-found|opengraph-image|twitter-image|icon|apple-icon|sitemap|robots|manifest)\.(m|c)?[jt]sx?$/
    const routable = appFiles.filter((f) => f.startsWith('app/') && ROUTE_CONVENTIONS.test(f))
    const collected = new Set([...pageFiles, ...layoutFiles, ...metadataRoutes, ...routeHandlers])

    // Purely presentational conventions render no data of their own.
    const NO_DATA_CONVENTIONS = /\/(loading|error|global-error)\.(m|c)?[jt]sx?$/

    for (const file of routable) {
      if (NO_DATA_CONVENTIONS.test(file)) continue
      expect([...collected], `${relative(process.cwd(), file)} is a real route but no collector in `
        + 'this file picks it up, so nothing checks its guards').toContain(file)
    }
  })

  test('the pages/ router is not used, because nothing here can see it', () => {
    // Every collector in this file, the proxy's route conventions, and the secret
    // scanner's route table all describe the APP router. A `pages/api/*.ts` file is
    // a real, registered endpoint that none of them models: one serving the
    // service-role key answered an anonymous GET with 200, no security headers and
    // no guard, while the whole suite and the secret scan stayed green.
    //
    // This project is App Router only, so the honest rule is that the other router
    // must not exist. If a later phase needs it, this test is where the guards for
    // it get written -- deleting the test is not the same as adding them.
    const pagesDirs = ['pages', 'src/pages'].filter((dir) => existsSync(dir))
    expect(pagesDirs, 'the pages/ router is invisible to every guard in this file and to '
      + 'scripts/check-no-secrets.ts; guard it there before adding it').toEqual([])
  })

  test('every file that could hide an action is checked for anonymous default exports', () => {
    // COMPILED_AS_APP narrows to app/ plus 'use server' modules, and a narrowing is
    // exactly what six review rounds kept finding. The claim is checkable: a server
    // action requires the 'use server' directive somewhere in its file, so a file
    // carrying that directive is in actionFiles by construction. This asserts it
    // rather than leaving it to be re-derived.
    for (const file of actionFiles) {
      expect(COMPILED_AS_APP, `${relative(process.cwd(), file)} declares 'use server' but is not `
        + 'checked for anonymous default exports').toContain(file)
    }
    for (const file of appFiles.filter((f) => SOURCE.test(f) && f.startsWith('app/'))) {
      expect(COMPILED_AS_APP, `${relative(process.cwd(), file)} is app code but is not checked`)
        .toContain(file)
    }
  })

  test('no route handler sits at a path the proxy matcher excludes', () => {
    // The matcher exempts media extensions so files in public/ are served. A route
    // handler can live at any path, including one ending .png -- and such a route
    // was served 200 anonymously with no proxy, no guard and no security headers.
    // Static assets and routes cannot be told apart by path, so the rule is that
    // our routes must not land on an excluded one.
    const MEDIA = /\.(svg|png|jpg|jpeg|gif|webp|avif|ico|woff|woff2|ttf|otf|eot|mp4|webm|mp3|wav)$/
    for (const file of routeHandlers) {
      const urlPath = '/' + relative('app', file).replace(/\/route\.(m|c)?[jt]sx?$/, '')
      expect(MEDIA.test(urlPath), `${relative(process.cwd(), file)} is served at ${urlPath}, which `
        + 'the proxy matcher excludes — it would be reachable with no auth and no security headers')
        .toBe(false)

      // A catch-all defeats the check from the other side: `app/[...path]/route.ts`
      // reads as the literal path `/[...path]`, which matches no media extension,
      // while at runtime it answers `/anything.png` -- which the matcher excludes.
      // The path cannot be tested, so the shape is banned.
      expect(/\[\[?\.\.\./.test(urlPath), `${relative(process.cwd(), file)} is a catch-all, so it `
        + 'serves paths ending in a media extension, which the proxy matcher excludes').toBe(false)
    }
  })
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

  // Quality bar 4: every mutating action writes an audit_log row. The database
  // triggers cover every ROW change, but an action whose effect is not a row write
  // -- switchBusinessAction sets a cookie -- leaves no trigger to fire. Nothing
  // connected server actions to the audit layer at all, so that action could have
  // shipped unaudited with the whole suite green.
  // An action's RETURN VALUE travels back to the browser inside the flight payload,
  // and it is the one channel scripts/check-no-secrets.ts cannot read: actions are
  // POSTed to the page they live on, the scan POSTs only route handlers, and
  // reaching an action needs a live session plus a CSRF token. Rather than claim
  // coverage the scan does not have, the channel is closed: every action in this
  // phase reports outcomes by redirecting, so none of them returns anything.
  test.each(everyAction)('%s → %s() returns nothing, so it cannot leak through the flight payload', (file, name) => {
    const source = code(join(process.cwd(), file))
    const signature = source.match(new RegExp(`${name}\\s*(?::[^=]*)?=?\\s*\\([^)]*\\)\\s*:\\s*([^{=]+)`))
    expect(signature?.[1]?.trim(), `${name} must declare an explicit Promise<void> return type; `
      + 'an action that returns a value sends it to the browser where nothing inspects it')
      .toBe('Promise<void>')

    // The declaration is not the value. `return { ... } as any` is assignable to
    // void, so it typechecks, the annotation still reads Promise<void>, and the
    // object ships in the flight reply -- DATABASE_URL and the service-role key were
    // delivered to a real POST with npm run verify at exit 0. So the BODY is checked
    // too: an action may `return` to exit early, but never a value.
    const body = bodyOf(join(process.cwd(), file), name)
    const valued = [...body.matchAll(/\breturn\b([^\n;}]*)/g)]
      .filter((m) => m[1]!.trim() !== '')
    expect(valued.map((m) => `return${m[1]}`), `${name} returns a value. Actions report `
      + 'outcomes by redirecting; a returned value reaches the browser through the flight '
      + 'payload, which the secret scan cannot read').toEqual([])
  })

  test.each(everyAction)('%s → %s() writes an audit_log row', (file, name) => {
    const body = bodyOf(join(process.cwd(), file), name)
    expect(body, `${name} mutates without recording an audit_log row`)
      .toMatch(/recordAudit(OrThrow|AnonymousAudit|Anonymous)?\(/)
  })
})

describe('every page', () => {
  // Pages that legitimately render before a full aal2 session exists. Each is
  // listed with the reason it is safe, and each is checked for what it MUST do.
  const PRE_MFA_PAGES = ['app/mfa/enroll/page.tsx', 'app/mfa/verify/page.tsx']

  // Pages that render no data at all, so there is nothing for a session to protect.
  // Anything added here must be genuinely dataless — a form or a redirect.
  const RENDERS_NO_DATA = ['app/login/page.tsx', 'app/page.tsx']

  // Every module each dataless page actually runs, read and confirmed to read no
  // tenant data. `csrfField()` reaches the session and Supabase modules to bind the
  // CSRF token to the signed-in subject; none of them queries a table.
  const DATALESS_PAGE_CLOSURES: Record<string, string[]> = {
    'app/login/page.tsx': [
      'app/login/page.tsx',
      'lib/env.ts',
      'lib/security/csrf-token.ts',
      'lib/security/csrf.ts',
      'lib/security/routes.ts',
      'lib/security/scan-mode.ts',
      'lib/security/session.ts',
      'lib/supabase/server.ts',
    ],
    'app/page.tsx': ['app/page.tsx', 'lib/security/routes.ts'],
  }

  test('there is at least one page to check', () => {
    expect(pageFiles.length).toBeGreaterThan(0)
  })

  test.each(pageFiles.map((f) => relative(process.cwd(), f)))('%s establishes a session before rendering', (file) => {
    const source = readFileSync(join(process.cwd(), file), 'utf8')

    if (RENDERS_NO_DATA.includes(file)) {
      // Hold them to that promise across everything the page RUNS, not just the
      // bytes in the page file. Greping the file alone certified /login as dataless
      // while it rendered every tenant in the system to an anonymous visitor
      // through a one-line service-role helper, with this suite at 166/166.
      // In the page file itself, merely CONSTRUCTING a client or reaching the
      // network is suspicious. `fetch(` is here because `.from(`/`.rpc(` is a model
      // of supabase-js, not of reading data: a raw fetch to PostgREST with the
      // service-role key matched neither, and served every tenant at 281/281 green.
      expect(source, `${file} is listed as dataless but reads data`)
        .not.toMatch(/\.from\(|\.rpc\(|createSupabase|\bfetch\(/)

      // Across the closure, an ENUMERATION rather than a pattern.
      //
      // Every pattern tried here has been a model of one library: .from(/.rpc( for
      // supabase-js, missing raw fetch, and it would equally miss a `pg` client,
      // supabase.auth.admin, or a route handler imported and called. There is no
      // finite list of ways to read data, so this asserts the opposite thing -- the
      // exact set of modules the page runs. Anything new in that set, reading data
      // by any means whatsoever, fails until a person reviews it and updates the
      // list. That is sound only because closureOf now proves the graph is complete
      // (it counts import sites against specifiers resolved) rather than returning a
      // short list when it fails to follow something.
      const reachable = moduleClosure(join(process.cwd(), file))
        .map((f) => relative(process.cwd(), f)).sort()
      expect(reachable, `the set of modules ${file} runs has changed. It is listed as `
        + 'rendering no data, and that claim covers everything it imports — read the new '
        + 'module and update DATALESS_PAGE_CLOSURES if it genuinely reads nothing')
        .toEqual(DATALESS_PAGE_CLOSURES[file])
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
  // Walking lib/ and app/ only, on .ts/.tsx only, meant a 'use client' component in
  // components/ importing the service-role client was seen by nothing. The action
  // collector was widened to the project root long before this one was.
  const importers = appFiles
    .filter((f) => SOURCE.test(f))
    .filter((f) => /supabase\/admin/.test(readFileSync(f, 'utf8')))
    .filter((f) => !f.endsWith('lib/supabase/admin.ts'))

  for (const file of importers) {
    const source = readFileSync(file, 'utf8')
    expect(source, `${file} imports the service-role client without 'server-only'`)
      .toMatch(/import ['"]server-only['"]/)
  }
})
