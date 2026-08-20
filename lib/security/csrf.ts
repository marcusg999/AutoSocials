import 'server-only'

import { createElement } from 'react'
import { cookies, headers } from 'next/headers'

import {
  CSRF_COOKIE_NAME,
  CSRF_FIELD_NAME,
  createCsrfToken,
  csrfCookieOptions,
  csrfTokensMatch,
} from '@/lib/security/csrf-token'

export { CSRF_COOKIE_NAME, CSRF_FIELD_NAME }

export class CsrfError extends Error {
  constructor(reason: string) {
    super(`CSRF check failed: ${reason}`)
    this.name = 'CsrfError'
  }
}

/**
 * Returns the token for this request. proxy.ts mints one on every matched
 * request, so the fallback path here only runs if the proxy was bypassed.
 */
async function currentCsrfToken(): Promise<string> {
  const cookieStore = await cookies()
  const existing = cookieStore.get(CSRF_COOKIE_NAME)?.value
  if (existing) return existing

  const token = createCsrfToken()
  try {
    cookieStore.set(CSRF_COOKIE_NAME, token, csrfCookieOptions())
  } catch {
    // A Server Component cannot set cookies. The proxy already did.
  }
  return token
}

/** Drop `{await csrfField()}` inside every <form> that performs a mutation. */
export async function csrfField() {
  const token = await currentCsrfToken()
  return createElement('input', { type: 'hidden', name: CSRF_FIELD_NAME, value: token })
}

/**
 * Rejects the request unless it came from our own origin AND carries the
 * synchroniser token that matches the httpOnly cookie.
 *
 * Origin/Referer alone is spoofable by non-browser clients and absent on some
 * requests, so the token is what actually makes forgery impossible.
 */
export async function assertCsrf(formData: FormData): Promise<void> {
  await assertSameOrigin()

  const cookieStore = await cookies()
  const expected = cookieStore.get(CSRF_COOKIE_NAME)?.value
  const provided = formData.get(CSRF_FIELD_NAME)

  if (!expected) throw new CsrfError('no token cookie on the request')
  if (typeof provided !== 'string' || provided.length === 0) {
    throw new CsrfError('no token in the submitted form')
  }
  if (!csrfTokensMatch(expected, provided)) throw new CsrfError('token mismatch')
}

/** The allowlist is exactly one entry: the host this request was addressed to. */
async function assertSameOrigin(): Promise<void> {
  const headerList = await headers()
  const host = headerList.get('x-forwarded-host') ?? headerList.get('host')
  if (!host) throw new CsrfError('request has no Host header')

  const stated = headerList.get('origin') ?? headerList.get('referer')
  if (!stated) throw new CsrfError('request states neither Origin nor Referer')

  let statedHost: string
  try {
    statedHost = new URL(stated).host
  } catch {
    throw new CsrfError('request states an unparseable Origin/Referer')
  }

  if (statedHost !== host) {
    throw new CsrfError(`cross-origin submission from ${statedHost}`)
  }
}
