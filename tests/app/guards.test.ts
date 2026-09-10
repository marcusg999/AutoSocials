/**
 * Structural guards: every server action is CSRF-protected, session-guarded and
 * audited, and every page establishes a session before it renders.
 *
 * This file used to be 607 lines. Most of that was machinery proving the file's own
 * collectors were complete — closure enumeration, invoke bans, completeness
 * assertions — built to defend a multi-tenant boundary against hostile co-tenants.
 * This is a single-operator tool: the tenant boundary now protects the owner's data
 * from the owner's own future bugs, and the runtime probe in check-no-secrets.ts
 * catches an actual data read far more directly than any static model of imports did.
 * What survives is the part that would catch a real mistake in a later phase:
 * a new action that forgets CSRF, a session check, or its audit row.
 */
import { describe, expect, test } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const SKIP = new Set(['node_modules', '.next', '.git', 'tests', 'supabase', 'scripts', '.probe'])

function walk(dir = '.', out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (SKIP.has(entry)) continue
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) walk(full, out)
    else out.push(full)
  }
  return out
}

/** Every extension Next compiles as application code. */
const SOURCE = /\.(m|c)?[jt]sx?$/
const files = walk().filter((f) => SOURCE.test(f))

/** Source with comments removed, so a commented-out guard cannot satisfy a match. */
const code = (file: string): string =>
  readFileSync(file, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1')

const actionFiles = files.filter((f) => /['"]use server['"]/.test(readFileSync(f, 'utf8')))
const pageFiles = files.filter((f) => /\/(page|default)\.(m|c)?[jt]sx?$/.test(f))
const routeHandlers = files.filter((f) => /\/route\.(m|c)?[jt]sx?$/.test(f))

/** Every exported binding in a 'use server' file is a callable entry point. */
function exportedActions(file: string): string[] {
  const source = code(file)
  const names = new Set<string>()
  for (const pattern of [
    /export\s+async\s+function\s+(\w+)/g,
    /export\s+(?:const|let|var)\s+(\w+)\s*=\s*async/g,
  ]) {
    for (const m of source.matchAll(pattern)) names.add(m[1]!)
  }
  return [...names]
}

/** One action's body, ending at the next export or declaration. */
function bodyOf(file: string, name: string): string {
  const source = code(file)
  const start = source.search(new RegExp(`(?:async\\s+function\\s+${name}\\b|(?:const|let|var)\\s+${name}\\b)`))
  if (start === -1) throw new Error(`could not locate ${name} in ${file}`)
  const rest = source.slice(start + 1)
  const next = rest.search(/\n(?:export\s|(?:async\s+)?function\s|const\s|let\s|var\s)/)
  return rest.slice(0, next === -1 ? undefined : next)
}

const everyAction = actionFiles.flatMap((file) =>
  exportedActions(file).map((name) => [relative(process.cwd(), file), name] as const))

test('there are actions and pages to check, so nothing here passes vacuously', () => {
  expect(everyAction.length).toBeGreaterThan(0)
  expect(pageFiles.length).toBeGreaterThan(0)
})

describe('every server action', () => {
  // Next routes Server Functions as POSTs to the page they live on, so the proxy's
  // matcher cannot be relied on to have covered them. Each action guards itself.
  test.each(everyAction)('%s → %s() checks CSRF before anything else', (file, name) => {
    const body = bodyOf(join(process.cwd(), file), name)
    expect(body, `${name} does not call assertCsrf`).toMatch(/await assertCsrf\(/)
    const csrfAt = body.indexOf('assertCsrf')
    const otherAwait = body.search(/await (?!assertCsrf)/)
    if (otherAwait !== -1) {
      expect(csrfAt, `${name} does something before checking CSRF`).toBeLessThan(otherAwait)
    }
  })

  // signInAction creates the session; the MFA flow and sign-out run before aal2
  // exists by necessity. Everything else needs a complete session.
  const CREATES_THE_SESSION = new Set(['signInAction'])
  const mayAcceptAal1 = (file: string, name: string) =>
    file.startsWith('app/mfa/') || name === 'signOutAction'

  test.each(everyAction)('%s → %s() establishes the session itself', (file, name) => {
    if (CREATES_THE_SESSION.has(name)) return
    const body = bodyOf(join(process.cwd(), file), name)
    if (mayAcceptAal1(file, name)) {
      expect(body, `${name} relies on the proxy alone`)
        .toMatch(/require(MfaSession|SignedInUser)OrThrow\(/)
    } else {
      expect(body, `${name} accepts a password-only session`).toMatch(/requireMfaSessionOrThrow\(/)
    }
  })

  test.each(everyAction)('%s → %s() writes an audit_log row', (file, name) => {
    expect(bodyOf(join(process.cwd(), file), name), `${name} mutates without an audit row`)
      .toMatch(/recordAudit|recordAnonymousAudit/)
  })

  // An action has several ways to hand a value to the browser — a redirect target, a
  // cookie, a header — and the secret scan reads none of them. Nothing in this phase
  // needs configuration inside an action, so the value is denied at its source. The
  // whole module, not one body: a helper below the action is callable from inside it.
  test.each(actionFiles.map((f) => relative(process.cwd(), f)))(
    '%s reads no environment variable', (file) => {
      expect(code(join(process.cwd(), file)), `${file} reads process.env`).not.toMatch(/process\.env/)
    })
})

describe('every page and route handler', () => {
  // These render before a session exists, by necessity. Each must still prove the
  // password step happened and redirect a fully verified user onward.
  const PRE_MFA = ['app/mfa/enroll/page.tsx', 'app/mfa/verify/page.tsx']
  // These render no tenant data at all — a form and a redirect.
  const PUBLIC = ['app/login/page.tsx', 'app/page.tsx']

  test.each(pageFiles.map((f) => relative(process.cwd(), f)))(
    '%s establishes a session before rendering', (file) => {
      const source = code(join(process.cwd(), file))
      if (PUBLIC.includes(file)) {
        // Held to that promise by the runtime probe in check-no-secrets.ts, which
        // renders every route anonymously and fails on an observed data read. That
        // is a stronger check than reading this file, and it needs no list.
        expect(source, `${file} is public but reads data`).not.toMatch(/\.from\(|\.rpc\(|createSupabase/)
        return
      }
      if (PRE_MFA.includes(file)) {
        expect(source).toMatch(/resolveSessionState\(/)
        return
      }
      expect(source, `${file} renders without requireMfaSession()`).toMatch(/requireMfaSession\(/)
    })

  test('every route handler guards each of its methods', () => {
    for (const file of routeHandlers) {
      const source = code(file)
      const pattern = /export\s+(?:async\s+function\s+|const\s+)(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/g
      const methods = [...source.matchAll(pattern)]
      expect(methods.length, `${relative(process.cwd(), file)} exports no HTTP method`).toBeGreaterThan(0)
      for (const m of methods) {
        const from = m.index!
        const rest = source.slice(from + 1)
        const next = rest.search(pattern)
        const body = rest.slice(0, next === -1 ? undefined : next)
        expect(body, `${file} ${m[1]} does not establish a session`).toMatch(/requireMfaSession(OrThrow)?\(/)
        if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(m[1]!)) {
          expect(body, `${file} ${m[1]} mutates without a CSRF check`).toMatch(/assertCsrf\(/)
        }
      }
    }
  })
})

test('the service-role client is only reachable from server-only modules', () => {
  // It bypasses row level security, so it must never be bundled for a browser.
  const importers = files
    .filter((f) => /supabase\/admin/.test(readFileSync(f, 'utf8')))
    .filter((f) => !f.endsWith('lib/supabase/admin.ts'))
  for (const file of importers) {
    expect(readFileSync(file, 'utf8'), `${file} imports the service-role client without 'server-only'`)
      .toMatch(/import ['"]server-only['"]/)
  }
})
