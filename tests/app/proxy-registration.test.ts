/**
 * QUALITY BAR #3 (registration half): the auth gate is actually wired into the build.
 *
 * The most dangerous failure mode in Next.js 16 is a proxy that is never invoked --
 * the app renders perfectly and is completely unguarded. Next 16 renamed
 * middleware.ts to proxy.ts, so the old filename produces exactly that.
 *
 * Note this reads functions-config-manifest.json, NOT middleware-manifest.json.
 * The latter is a legacy webpack artifact that Turbopack leaves empty on every
 * build, so checking it would report a false failure every time.
 */
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, test } from 'vitest'

const MANIFEST = join(process.cwd(), '.next/server/functions-config-manifest.json')

function manifest() {
  if (!existsSync(MANIFEST)) {
    throw new Error('No production build found. Run `npm run build` before this test.')
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

  test.each(['/_next/static/chunk.js', '/_next/image', '/favicon.ico', '/logo.png'])(
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
