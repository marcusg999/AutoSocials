/**
 * CSRF primitives shared by proxy.ts (which issues the token) and lib/security/csrf.ts
 * (which renders and checks it).
 *
 * This module deliberately imports nothing from next/headers and is not marked
 * server-only, because the proxy bundle has to be able to load it.
 */
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import type { NextRequest, NextResponse } from 'next/server'

export const CSRF_COOKIE_NAME = 'pd_csrf'
export const CSRF_FIELD_NAME = 'csrf_token'

const EIGHT_HOURS_IN_SECONDS = 60 * 60 * 8

export function createCsrfToken(): string {
  return randomBytes(32).toString('base64url')
}

export function csrfCookieOptions() {
  return {
    httpOnly: true,
    // The token is only ever compared server-side, so the browser never needs to read it.
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax' as const,
    path: '/',
    maxAge: EIGHT_HOURS_IN_SECONDS,
  }
}

/**
 * Constant-time comparison. Both sides are hashed first so that a length
 * mismatch neither throws nor leaks the expected token's length.
 */
export function csrfTokensMatch(expected: string, provided: string): boolean {
  const a = createHash('sha256').update(expected).digest()
  const b = createHash('sha256').update(provided).digest()
  return timingSafeEqual(a, b)
}

/**
 * Makes sure this request carries a CSRF token, minting one if not.
 *
 * The new token is written onto the *request* as well, so the page rendered on
 * this very request embeds the same value the browser is about to store.
 */
export function issueCsrfToken(request: NextRequest): { token: string; isNew: boolean } {
  const existing = request.cookies.get(CSRF_COOKIE_NAME)?.value
  if (existing) return { token: existing, isNew: false }

  const token = createCsrfToken()
  request.cookies.set(CSRF_COOKIE_NAME, token)
  return { token, isNew: true }
}

export function attachCsrfCookie(response: NextResponse, token: string): void {
  response.cookies.set(CSRF_COOKIE_NAME, token, csrfCookieOptions())
}
