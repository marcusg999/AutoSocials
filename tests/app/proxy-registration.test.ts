/**
 * QUALITY BAR #3 (registration half): the auth gate is actually wired into the build.
 *
 * The most dangerous failure mode in Next.js 16 is a proxy that is never invoked --
 * the app renders perfectly and is completely unguarded. Next 16 renamed
 * middleware.ts to proxy.ts, so the old filename produces exactly that.
 *
 * Run `npm run verify` rather than `npm test` alone: this file reads BUILD OUTPUT,
 * so the build has to be current. There is a staleness guard below, but the script
 * ordering is what stops the question arising.
 *
 * Note this reads functions-config-manifest.json, NOT middleware-manifest.json.
 * The latter is a legacy webpack artifact that Turbopack leaves empty on every
 * build, so checking it would report a false failure every time.
 */
import { existsSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, test } from 'vitest'

const MANIFEST = join(process.cwd(), '.next/server/functions-config-manifest.json')

function manifest() {
  if (!existsSync(MANIFEST)) {
    throw new Error('No production build found. Run `npm run build` before this test.')
  }

  // This test reads BUILD OUTPUT, so a stale .next reports on source that no longer
  // exists. That is not hypothetical: a matcher change was once verified green
  // against a manifest built before the change, and the contradiction only surfaced
  // on the next build. Refuse to answer rather than answer about the wrong code.
  const builtAt = statSync(MANIFEST).mtimeMs
  const sourceAt = statSync(join(process.cwd(), 'proxy.ts')).mtimeMs
  if (sourceAt > builtAt) {
    throw new Error(
      'proxy.ts is newer than the production build, so this test would be checking '
      + 'stale output. Run `npm run build` and try again.',
    )
  }

  return JSON.parse(readFileSync(MANIFEST, 'utf8'))
}

describe('the proxy is registered in the production build', () => {
  test('a proxy function exists in the build manifest', () => {
    const entry = manifest().functions?.['/_middleware']
    expect(entry, 'proxy.ts was not registered — is the file named correctly?').toBeTruthy()
    expect(entry.matchers?.length).toBeGreaterThan(0)
  })

  test('the proxy runs on the Node.js runtime', () => {
    // Next 16 proxies default to Node.js; the Supabase server client needs it.
    expect(manifest().functions['/_middleware'].runtime).toBe('nodejs')
  })

  test.each([
    '/', '/dashboard', '/dashboard/accounts', '/dashboard/calendar',
    '/dashboard/composer', '/login', '/mfa/enroll', '/mfa/verify',
  ])('the proxy runs for %s', (path) => {
    const regexp = new RegExp(manifest().functions['/_middleware'].matchers[0].regexp)
    expect(regexp.test(path), `${path} is not covered by the proxy matcher`).toBe(true)
  })

  test.each([
    '/robots.txt', '/sitemap.xml', '/dashboard/export.json', '/reports/tenant.csv',
  ])('the proxy still runs for %s, which could carry tenant data', (path) => {
    // Excluding these by extension is how an export endpoint ends up unguarded.
    const regexp = new RegExp(manifest().functions['/_middleware'].matchers[0].regexp)
    expect(regexp.test(path)).toBe(true)
  })

  test.each([
    '/_next/static/chunk.js', '/_next/image', '/favicon.ico',
    '/logo.png', '/hero.webp', '/font.woff2', '/promo.mp4',
  ])(
    'the proxy is skipped for the static asset %s',
    (path) => {
      const regexp = new RegExp(manifest().functions['/_middleware'].matchers[0].regexp)
      expect(regexp.test(path)).toBe(false)
    }
  )

  test('the root project has no stale middleware.ts, which Next 16 would ignore', () => {
    expect(existsSync(join(process.cwd(), 'middleware.ts'))).toBe(false)
    expect(existsSync(join(process.cwd(), 'proxy.ts'))).toBe(true)
  })
})
