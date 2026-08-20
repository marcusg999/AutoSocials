/**
 * CSRF: every mutation must come from one of our own origins AND carry a token
 * this server signed, matching the httpOnly cookie.
 *
 * These tests drive assertCsrf() itself, not just the token helpers, because the
 * two bugs a previous revision shipped both lived in the checking code rather than
 * in the token: the origin was compared against a client-supplied header, and a
 * planted cookie was accepted because it matched the field the attacker also sent.
 */
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

process.env.CSRF_SIGNING_SECRET ??= 'test-signing-secret-at-least-32-characters-long'

let cookieJar = new Map<string, string>()
let headerBag = new Headers()

vi.mock('next/headers', () => ({
  cookies: async () => ({
    get: (name: string) => (cookieJar.has(name) ? { name, value: cookieJar.get(name)! } : undefined),
    set: (name: string, value: string) => { cookieJar.set(name, value) },
    delete: (name: string) => { cookieJar.delete(name) },
  }),
  headers: async () => headerBag,
}))

const {
  CSRF_COOKIE_NAME, CSRF_FIELD_NAME, createCsrfToken, csrfCookieOptions,
  csrfTokensMatch, isValidCsrfToken, issueCsrfToken, attachCsrfCookie,
} = await import('@/lib/security/csrf-token')
const { assertCsrf, CsrfError, rotateCsrfToken, clearCsrfToken } = await import('@/lib/security/csrf')

const OUR_ORIGIN = 'https://postdeck.example.com'

beforeEach(() => {
  cookieJar = new Map()
  headerBag = new Headers()
  process.env.APP_ORIGIN = OUR_ORIGIN
  vi.stubEnv('NODE_ENV', 'production')
})
afterEach(() => { vi.unstubAllEnvs() })

/** Builds a submission: what the cookie holds, what the form sent, where it came from. */
function submission({ cookie, field, origin, host }: {
  cookie?: string; field?: string; origin?: string; host?: string
}) {
  if (cookie !== undefined) cookieJar.set(CSRF_COOKIE_NAME, cookie)
  if (origin !== undefined) headerBag.set('origin', origin)
  if (host !== undefined) headerBag.set('x-forwarded-host', host)
  const form = new FormData()
  if (field !== undefined) form.set(CSRF_FIELD_NAME, field)
  return form
}

describe('a legitimate submission is accepted', () => {
  test('correct token, our origin', async () => {
    const token = createCsrfToken()
    await expect(assertCsrf(submission({ cookie: token, field: token, origin: OUR_ORIGIN })))
      .resolves.toBeUndefined()
  })
})

describe('the origin check cannot be talked around', () => {
  test('a cross-origin post is refused', async () => {
    const token = createCsrfToken()
    await expect(assertCsrf(submission({ cookie: token, field: token, origin: 'https://evil.example' })))
      .rejects.toThrow(/cross-origin/i)
  })

  test('spoofing x-forwarded-host does NOT make evil.example look like us', async () => {
    // The regression that matters. An earlier version compared Origin against
    // x-forwarded-host, so an attacker who sent both headers passed the check.
    const token = createCsrfToken()
    await expect(assertCsrf(submission({
      cookie: token, field: token,
      origin: 'https://evil.example',
      host: 'evil.example',
    }))).rejects.toThrow(/cross-origin/i)
  })

  test('a request with no Origin or Referer at all is refused', async () => {
    const token = createCsrfToken()
    await expect(assertCsrf(submission({ cookie: token, field: token })))
      .rejects.toThrow(/neither Origin nor Referer/i)
  })

  test('in production, an unset APP_ORIGIN fails closed rather than open', async () => {
    delete process.env.APP_ORIGIN
    const token = createCsrfToken()
    await expect(assertCsrf(submission({ cookie: token, field: token, origin: OUR_ORIGIN })))
      .rejects.toThrow(/APP_ORIGIN must be set/i)
  })
})

describe('the token cannot be forged or planted', () => {
  test('a value the attacker made up is rejected even when both halves agree', async () => {
    // The other regression that matters. The old check was "cookie === field",
    // which an attacker satisfies trivially by supplying both.
    await expect(assertCsrf(submission({
      cookie: 'ATTACKER_PLANTED_VALUE',
      field: 'ATTACKER_PLANTED_VALUE',
      origin: OUR_ORIGIN,
    }))).rejects.toThrow(CsrfError)
  })

  test('a token with a tampered signature is rejected', async () => {
    const token = createCsrfToken()
    const tampered = token.slice(0, -4) + 'AAAA'
    await expect(assertCsrf(submission({ cookie: tampered, field: tampered, origin: OUR_ORIGIN })))
      .rejects.toThrow(CsrfError)
  })

  test('an expired token is rejected', () => {
    const [nonce] = createCsrfToken().split('.')
    const past = `${nonce}.${Date.now() - 1000}.whatever`
    expect(isValidCsrfToken(past)).toBe(false)
  })

  test('a valid cookie with a mismatched form field is rejected', async () => {
    await expect(assertCsrf(submission({
      cookie: createCsrfToken(), field: createCsrfToken(), origin: OUR_ORIGIN,
    }))).rejects.toThrow(/mismatch/i)
  })

  test('a missing form field is rejected', async () => {
    await expect(assertCsrf(submission({ cookie: createCsrfToken(), origin: OUR_ORIGIN })))
      .rejects.toThrow(/no token in the submitted form/i)
  })

  test('a missing cookie is rejected', async () => {
    await expect(assertCsrf(submission({ field: createCsrfToken(), origin: OUR_ORIGIN })))
      .rejects.toThrow(/no token cookie/i)
  })
})

describe('the token itself', () => {
  test('is signed, unguessable and unique', () => {
    const a = createCsrfToken()
    const b = createCsrfToken()
    expect(a).not.toBe(b)
    expect(a.split('.')).toHaveLength(3)
    expect(isValidCsrfToken(a)).toBe(true)
  })

  test('a length mismatch is rejected rather than throwing', () => {
    expect(() => csrfTokensMatch(createCsrfToken(), 'short')).not.toThrow()
    expect(csrfTokensMatch(createCsrfToken(), 'short')).toBe(false)
  })

  test('a planted cookie is replaced, not trusted, when the proxy sees it', () => {
    const request = new NextRequest(new URL('https://postdeck.test/login'))
    request.cookies.set(CSRF_COOKIE_NAME, 'ATTACKER_PLANTED_VALUE')
    const issued = issueCsrfToken(request)
    expect(issued.isNew, 'an unsigned cookie must be replaced').toBe(true)
    expect(issued.token).not.toBe('ATTACKER_PLANTED_VALUE')
    expect(isValidCsrfToken(issued.token)).toBe(true)
  })

  test('a token we did sign is reused across the same session', () => {
    const request = new NextRequest(new URL('https://postdeck.test/login'))
    const first = issueCsrfToken(request)
    expect(first.isNew).toBe(true)
    const second = issueCsrfToken(request)
    expect(second.isNew).toBe(false)
    expect(second.token).toBe(first.token)
  })
})

describe('the cookie', () => {
  test('is httpOnly, same-site and path-scoped', () => {
    const options = csrfCookieOptions()
    expect(options.httpOnly, 'the browser must never be able to read it').toBe(true)
    expect(options.sameSite).toBe('lax')
    expect(options.path).toBe('/')
    expect(options.maxAge).toBeGreaterThan(0)
  })

  test('is attached to the response so the browser stores it', () => {
    const response = NextResponse.next()
    const token = createCsrfToken()
    attachCsrfCookie(response, token)
    expect(response.cookies.get(CSRF_COOKIE_NAME)?.httpOnly).toBe(true)
  })

  test('is rotated at sign-in and cleared at sign-out', async () => {
    const before = createCsrfToken()
    cookieJar.set(CSRF_COOKIE_NAME, before)

    await rotateCsrfToken()
    const after = cookieJar.get(CSRF_COOKIE_NAME)!
    expect(after, 'a token minted before sign-in must not survive it').not.toBe(before)
    expect(isValidCsrfToken(after)).toBe(true)

    await clearCsrfToken()
    expect(cookieJar.has(CSRF_COOKIE_NAME)).toBe(false)
  })
})

test('no token is ever placed anywhere the browser could read it', async () => {
  const { readFileSync, readdirSync, statSync } = await import('node:fs')
  const { join } = await import('node:path')

  const walk = (dir: string, out: string[] = []): string[] => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry)
      if (statSync(full).isDirectory()) walk(full, out)
      else if (/\.(ts|tsx)$/.test(full)) out.push(full)
    }
    return out
  }

  const sources = [...walk('app'), ...walk('lib'), 'proxy.ts']
  const offenders = sources.filter((file) =>
    /localStorage|sessionStorage/.test(readFileSync(file, 'utf8')))
  expect(offenders, 'tokens must never be stored in web storage').toEqual([])
})
