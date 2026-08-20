/**
 * CSRF primitives shared by proxy.ts (which issues the token) and lib/security/csrf.ts
 * (which renders and checks it).
 *
 * The token is SIGNED. An earlier version stored a random value in a cookie and
 * checked only that the cookie and the form field matched each other -- which any
 * attacker who could write the cookie could satisfy trivially, because both halves
 * were their own value. Verifying an HMAC proves this server minted the token.
 *
 * This module deliberately imports nothing from next/headers and is not marked
 * server-only, because the proxy bundle has to be able to load it.
 */
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import type { NextRequest, NextResponse } from 'next/server'

export const CSRF_COOKIE_NAME = 'pd_csrf'
export const CSRF_FIELD_NAME = 'csrf_token'

const TOKEN_LIFETIME_MS = 1000 * 60 * 60 * 8

function signingSecret(): string {
  const secret = process.env.CSRF_SIGNING_SECRET
  if (!secret || secret.length < 32) {
    throw new Error('CSRF_SIGNING_SECRET must be set to at least 32 characters')
  }
  return secret
}

function sign(payload: string): string {
  return createHmac('sha256', signingSecret()).update(payload).digest('base64url')
}

/** A token is `<nonce>.<expiry>.<signature>`. */
export function createCsrfToken(): string {
  const nonce = randomBytes(32).toString('base64url')
  const expiry = String(Date.now() + TOKEN_LIFETIME_MS)
  return `${nonce}.${expiry}.${sign(`${nonce}.${expiry}`)}`
}

/** True only for a token this server signed, that has not expired. */
export function isValidCsrfToken(token: string): boolean {
  const parts = token.split('.')
  if (parts.length !== 3) return false

  const [nonce, expiry, signature] = parts as [string, string, string]
  if (!/^\d+$/.test(expiry) || Number(expiry) < Date.now()) return false

  return constantTimeEquals(signature, sign(`${nonce}.${expiry}`))
}

export function csrfCookieOptions() {
  return {
    httpOnly: true,
    // The token is only ever compared server-side, so the browser never needs to read it.
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax' as const,
    path: '/',
    maxAge: TOKEN_LIFETIME_MS / 1000,
  }
}

/**
 * Constant-time comparison. Both sides are hashed to a fixed width first so that a
 * length mismatch neither throws nor leaks the expected value's length.
 */
export function constantTimeEquals(expected: string, provided: string): boolean {
  const a = createHmac('sha256', 'compare').update(expected).digest()
  const b = createHmac('sha256', 'compare').update(provided).digest()
  return timingSafeEqual(a, b)
}

/** Both halves must match each other AND be a token this server actually signed. */
export function csrfTokensMatch(expected: string, provided: string): boolean {
  if (!isValidCsrfToken(expected)) return false
  return constantTimeEquals(expected, provided)
}

/**
 * Makes sure this request carries a valid CSRF token, minting one if it does not.
 *
 * A cookie that fails signature verification is REPLACED rather than trusted, so a
 * planted value cannot survive into the comparison.
 *
 * The new token is written onto the *request* as well, so the page rendered on this
 * very request embeds the same value the browser is about to store.
 */
export function issueCsrfToken(request: NextRequest): { token: string; isNew: boolean } {
  const existing = request.cookies.get(CSRF_COOKIE_NAME)?.value
  if (existing && isValidCsrfToken(existing)) return { token: existing, isNew: false }

  const token = createCsrfToken()
  request.cookies.set(CSRF_COOKIE_NAME, token)
  return { token, isNew: true }
}

export function attachCsrfCookie(response: NextResponse, token: string): void {
  response.cookies.set(CSRF_COOKIE_NAME, token, csrfCookieOptions())
}
