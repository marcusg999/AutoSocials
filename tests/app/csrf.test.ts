/**
 * CSRF: every mutation is protected by a synchroniser token in an httpOnly cookie,
 * compared in constant time against a hidden form field.
 */
import { describe, expect, test } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'
import {
  CSRF_COOKIE_NAME,
  createCsrfToken,
  csrfCookieOptions,
  csrfTokensMatch,
  issueCsrfToken,
  attachCsrfCookie,
} from '@/lib/security/csrf-token'

describe('the token itself', () => {
  test('is long and random', () => {
    const a = createCsrfToken()
    const b = createCsrfToken()
    expect(a).not.toBe(b)
    // 32 random bytes, base64url encoded.
    expect(a.length).toBeGreaterThanOrEqual(43)
    expect(a).toMatch(/^[A-Za-z0-9_-]+$/)
  })

  test('matches itself and nothing else', () => {
    const token = createCsrfToken()
    expect(csrfTokensMatch(token, token)).toBe(true)
    expect(csrfTokensMatch(token, createCsrfToken())).toBe(false)
    expect(csrfTokensMatch(token, '')).toBe(false)
    expect(csrfTokensMatch(token, token.slice(0, -1))).toBe(false)
    expect(csrfTokensMatch(token, token + 'x')).toBe(false)
  })

  test('a length mismatch is rejected rather than throwing', () => {
    // Both sides are hashed before comparison, so timingSafeEqual always gets
    // equal-length buffers and the expected token's length never leaks.
    expect(() => csrfTokensMatch(createCsrfToken(), 'short')).not.toThrow()
    expect(csrfTokensMatch(createCsrfToken(), 'short')).toBe(false)
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

  test('is issued once and then reused, so a page render and its form agree', () => {
    const request = new NextRequest(new URL('https://postdeck.test/login'))
    const first = issueCsrfToken(request)
    expect(first.isNew).toBe(true)

    // The token is written back onto the request, so this same render sees it.
    expect(request.cookies.get(CSRF_COOKIE_NAME)?.value).toBe(first.token)

    const second = issueCsrfToken(request)
    expect(second.isNew).toBe(false)
    expect(second.token).toBe(first.token)
  })

  test('is attached to the response so the browser stores it', () => {
    const response = NextResponse.next()
    const token = createCsrfToken()
    attachCsrfCookie(response, token)
    const cookie = response.cookies.get(CSRF_COOKIE_NAME)
    expect(cookie?.value).toBe(token)
    expect(cookie?.httpOnly).toBe(true)
  })
})

test('no token is ever placed anywhere the browser could read it', async () => {
  // A regression guard for the "no tokens in localStorage" rule.
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
