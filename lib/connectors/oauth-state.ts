import 'server-only'

import { createHmac, randomBytes } from 'node:crypto'
import { cookies } from 'next/headers'

import { constantTimeEquals } from '@/lib/security/csrf-token'
import { isProduction } from '@/lib/env'

/**
 * The OAuth `state` parameter, signed and bound to a cookie.
 *
 * Phase 1 deleted the only code-exchange route it had and left a note saying to
 * bring one back "with a state parameter bound to a cookie when a phase actually
 * introduces OAuth". This is that.
 *
 * Two properties, and both are needed:
 *
 *   SIGNED, so a caller cannot mint a state we will accept. Without this, anyone
 *   can send the browser to our callback with a code they obtained themselves.
 *
 *   BOUND TO A COOKIE, so a state minted for one browser cannot be replayed in
 *   another. A signature alone proves we issued it, not that we issued it to the
 *   person presenting it — the same distinction the CSRF token makes, for the same
 *   reason. This is what stops an attacker completing a connect flow in the
 *   owner's session and attaching THEIR social account to the owner's business.
 *
 * The state also carries the business the connect was started from, so the callback
 * cannot be pointed at a different tenant by editing a query parameter.
 */

const STATE_COOKIE = isProduction() ? '__Host-pd_oauth' : 'pd_oauth'
const STATE_LIFETIME_MS = 1000 * 60 * 10

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

export interface OAuthState {
  businessId: string
  platform: string
}

/** Mints a state, sets the matching cookie, and returns the value for the URL. */
export async function issueOAuthState(state: OAuthState): Promise<string> {
  const nonce = randomBytes(32).toString('base64url')
  const expiry = String(Date.now() + STATE_LIFETIME_MS)
  const payload = `${nonce}.${expiry}.${state.businessId}.${state.platform}`
  const value = `${payload}.${sign(payload)}`

  const jar = await cookies()
  jar.set(STATE_COOKIE, value, {
    httpOnly: true,
    sameSite: 'lax',      // 'lax' so the cookie survives the provider's redirect back
    secure: isProduction(),
    path: '/',
    maxAge: STATE_LIFETIME_MS / 1000,
  })
  return value
}

/**
 * Verifies the state from the callback URL against the cookie, and returns what it
 * carried. Null on any failure — there is no partial success worth acting on.
 */
export async function consumeOAuthState(fromUrl: string | null): Promise<OAuthState | null> {
  const jar = await cookies()
  const fromCookie = jar.get(STATE_COOKIE)?.value ?? null
  // Single use, whatever happens next.
  jar.delete(STATE_COOKIE)

  if (!fromUrl || !fromCookie) return null
  if (!constantTimeEquals(fromCookie, fromUrl)) return null

  const parts = fromUrl.split('.')
  if (parts.length !== 5) return null
  const [nonce, expiry, businessId, platform, signature] = parts as [string, string, string, string, string]
  if (!constantTimeEquals(sign(`${nonce}.${expiry}.${businessId}.${platform}`), signature)) return null
  if (!Number.isFinite(Number(expiry)) || Number(expiry) < Date.now()) return null

  return { businessId, platform }
}
