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

/**
 * Issues a brand-new CSRF token bound to the given user. Called after a successful
 * sign-in, so the token that follows a session change belongs to the new session
 * and a token minted before it cannot be reused across the boundary.
 */
export async function rotateCsrfToken(subject: string | null): Promise<void> {
  const cookieStore = await cookies()
  cookieStore.set(CSRF_COOKIE_NAME, createCsrfToken(subject), csrfCookieOptions())
}

/** Removes the token entirely, on sign-out. */
export async function clearCsrfToken(): Promise<void> {
  const cookieStore = await cookies()
  cookieStore.delete(CSRF_COOKIE_NAME)
}

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

  const token = createCsrfToken(await currentSubject())
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
 * Rejects the request unless it came from one of our own origins AND carries a
 * server-signed token matching the httpOnly cookie.
 *
 * Two independent checks, because each covers the other's gap: the Origin header
 * is absent on some legitimate requests and spoofable by non-browser clients, and
 * the token alone would not stop a same-origin script. Both must pass.
 */
export async function assertCsrf(formData: FormData): Promise<void> {
  await assertSameOrigin()

  const subject = await currentSubject()
  const cookieStore = await cookies()
  const expected = cookieStore.get(CSRF_COOKIE_NAME)?.value
  const provided = formData.get(CSRF_FIELD_NAME)

  if (!expected) throw new CsrfError('no token cookie on the request')
  if (typeof provided !== 'string' || provided.length === 0) {
    throw new CsrfError('no token in the submitted form')
  }
  if (!csrfTokensMatch(expected, provided, subject)) {
    throw new CsrfError('token mismatch, or the token was not issued to this session')
  }
}

/**
 * The signed-in user's id, or null before sign-in.
 *
 * Read straight from the verified session rather than from anything the request
 * supplies, because it is half of what the CSRF token is signed over.
 */
async function currentSubject(): Promise<string | null> {
  const { resolveSessionState } = await import('@/lib/security/session')
  const state = await resolveSessionState()
  if (state.status === 'verified') return state.session.userId
  if (state.status === 'anonymous') return null
  return state.user.id
}

/**
 * Rejects anything whose Origin is not one of ours.
 *
 * The allowlist comes from configuration, NOT from the request. An earlier version
 * compared Origin against `x-forwarded-host` -- a header the client supplies -- so
 * the rule was really "Origin must match whatever host the request claims to be
 * for", which any attacker can satisfy by sending both.
 */
async function assertSameOrigin(): Promise<void> {
  const headerList = await headers()

  const stated = headerList.get('origin') ?? headerList.get('referer')
  if (!stated) throw new CsrfError('request states neither Origin nor Referer')

  let statedOrigin: string
  try {
    statedOrigin = new URL(stated).origin
  } catch {
    throw new CsrfError('request states an unparseable Origin/Referer')
  }

  const allowed = allowedOrigins(headerList)
  if (!allowed.includes(statedOrigin)) {
    throw new CsrfError(`cross-origin submission from ${statedOrigin}`)
  }
}

/**
 * In production the allowlist is exactly what APP_ORIGIN says, and nothing else.
 * Only in development does it fall back to the request's own host, so that
 * localhost and preview ports work without configuration.
 */
function allowedOrigins(headerList: Headers): string[] {
  const configured = (process.env.APP_ORIGIN ?? '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean)
    .map((value) => {
      try {
        return new URL(value).origin
      } catch {
        throw new CsrfError(`APP_ORIGIN contains an unparseable value: ${value}`)
      }
    })

  if (process.env.NODE_ENV === 'production') {
    if (configured.length === 0) {
      throw new CsrfError('APP_ORIGIN must be set in production so cross-origin posts can be refused')
    }
    return configured
  }

  const host = headerList.get('host')
  const development = host ? [`http://${host}`, `https://${host}`] : []
  return [...configured, ...development]
}
