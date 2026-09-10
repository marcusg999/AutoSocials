/**
 * QUALITY BAR #3 (application half): no authenticated route is reachable without
 * password plus TOTP.
 *
 * The Supabase session lookup is stubbed so each test can state exactly what kind
 * of visitor is knocking — signed out, password-only, enrolled-but-unchallenged, or
 * fully verified — and assert where the proxy sends them. The decision logic under
 * test is the real thing.
 */
import { beforeEach, describe, expect, test, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

type Aal = { currentLevel: string | null; nextLevel: string | null } | null
let stubbedUser: { id: string } | null = null
let stubbedAal: Aal = null

vi.mock('@/lib/supabase/proxy', () => ({
  updateSession: vi.fn(async () => ({
    response: NextResponse.next(),
    supabase: {} as never,
    user: stubbedUser,
    aal: stubbedAal,
  })),
}))

const { proxy, config } = await import('@/proxy')

function get(path: string) {
  return new NextRequest(new URL(`https://postdeck.test${path}`), { method: 'GET' })
}

/** Where did the proxy send this request? null means "allowed through". */
async function destinationOf(path: string): Promise<string | null> {
  const response = await proxy(get(path))
  if (response.status !== 307 && response.status !== 308) return null
  return new URL(response.headers.get('location')!).pathname
}

function signedOut() { stubbedUser = null; stubbedAal = null }
function passwordOnlyNoFactor() { stubbedUser = { id: 'u1' }; stubbedAal = { currentLevel: 'aal1', nextLevel: 'aal1' } }
function passwordOnlyWithFactor() { stubbedUser = { id: 'u1' }; stubbedAal = { currentLevel: 'aal1', nextLevel: 'aal2' } }
function fullyVerified() { stubbedUser = { id: 'u1' }; stubbedAal = { currentLevel: 'aal2', nextLevel: 'aal2' } }

const PROTECTED = ['/', '/dashboard', '/dashboard/composer', '/dashboard/calendar', '/dashboard/accounts', '/anything/else']

beforeEach(() => { signedOut() })

describe('a signed-out visitor', () => {
  test.each(PROTECTED)('is sent to /login from %s', async (path) => {
    expect(await destinationOf(path)).toBe('/login')
  })

  test('may see the login page itself', async () => {
    expect(await destinationOf('/login')).toBeNull()
  })
})

describe('a visitor with the right password but no TOTP', () => {
  test.each(PROTECTED)('is sent to enrol MFA from %s, never to the page', async (path) => {
    passwordOnlyNoFactor()
    expect(await destinationOf(path)).toBe('/mfa/enroll')
  })

  test('cannot skip enrolment by going straight to the verify page', async () => {
    passwordOnlyNoFactor()
    expect(await destinationOf('/mfa/verify')).toBe('/mfa/enroll')
  })

  test('is bounced off the login page rather than being allowed to loop', async () => {
    passwordOnlyNoFactor()
    expect(await destinationOf('/login')).toBe('/mfa/enroll')
  })
})

describe('a visitor who has enrolled TOTP but not answered the challenge', () => {
  test.each(PROTECTED)('is sent to the TOTP challenge from %s', async (path) => {
    passwordOnlyWithFactor()
    expect(await destinationOf(path)).toBe('/mfa/verify')
  })

  test('may see the challenge page', async () => {
    passwordOnlyWithFactor()
    expect(await destinationOf('/mfa/verify')).toBeNull()
  })

  test('cannot go back and enrol a second, attacker-controlled factor', async () => {
    passwordOnlyWithFactor()
    expect(await destinationOf('/mfa/enroll')).toBe('/mfa/verify')
  })
})

describe('a fully verified visitor', () => {
  test.each(PROTECTED)('is allowed through to %s', async (path) => {
    fullyVerified()
    expect(await destinationOf(path)).toBeNull()
  })

  test('is redirected away from the login and MFA pages', async () => {
    fullyVerified()
    expect(await destinationOf('/login')).toBe('/dashboard')
    expect(await destinationOf('/mfa/enroll')).toBe('/dashboard')
    expect(await destinationOf('/mfa/verify')).toBe('/dashboard')
  })
})

describe('security response headers', () => {
  test('every response carries the full set, even a redirect to login', async () => {
    signedOut()
    const response = await proxy(get('/dashboard'))
    expect(response.headers.get('X-Frame-Options')).toBe('DENY')
    expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff')
    expect(response.headers.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin')
    expect(response.headers.get('Strict-Transport-Security')).toMatch(/max-age=\d+/)
    const csp = response.headers.get('Content-Security-Policy') ?? ''
    expect(csp).toContain("frame-ancestors 'none'")
    expect(csp).toContain("object-src 'none'")
    expect(csp).toMatch(/script-src [^;]*'nonce-/)
  })
})

test('the matcher does not accidentally exclude any protected route', () => {
  // A matcher that misses a path silently disables the gate for it.
  const pattern = new RegExp((config.matcher as string[])[0].replace(/^\//, '^/'))
  for (const path of PROTECTED) {
    expect(pattern.test(path), `${path} is not covered by the proxy matcher`).toBe(true)
  }
})
