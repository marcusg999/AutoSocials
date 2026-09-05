import 'server-only'

import { metaAppCredentials } from '@/lib/env'
import type { Connector, DiscoveredAccount } from '@/lib/connectors/types'

/**
 * The Facebook / Instagram connector.
 *
 * Meta's flow is three exchanges, not one, and each step matters:
 *
 *   1. code -> short-lived user token          (~1 hour)
 *   2. short-lived -> long-lived user token    (~60 days)
 *   3. long-lived user token -> PAGE tokens    (one per Page the user granted)
 *
 * We store the PAGE tokens, never the user token. A page token is scoped to one
 * Page, so a leak costs one account rather than everything the person can reach,
 * and it is what publishing will actually need in a later phase. The user token is
 * used once, in this process, and never written anywhere.
 */

const GRAPH = 'https://graph.facebook.com/v21.0'

/**
 * Scopes are requested explicitly and checked afterwards. Meta returns what was
 * GRANTED, which can be fewer than what was asked, and a user can revoke one later
 * from their own settings — so a later phase must read the stored scopes rather
 * than assume this list.
 */
const SCOPES = [
  'pages_show_list',
  'pages_manage_posts',
  'pages_read_engagement',
  'instagram_basic',
  'instagram_content_publish',
  'business_management',
]

/** Meta returns errors as 200s with an `error` object often enough to check both. */
async function graph(url: string): Promise<Record<string, unknown>> {
  const response = await fetch(url, { cache: 'no-store' })
  const body = (await response.json()) as Record<string, unknown>
  const error = body.error as { message?: string; type?: string } | undefined
  if (!response.ok || error) {
    // The message is shown to the operator and written to the audit log, so it must
    // not carry the token. Meta echoes request parameters in some error bodies.
    throw new Error(`Meta rejected the request: ${error?.message ?? response.status}`)
  }
  return body
}

export const metaConnector: Connector = {
  platform: 'facebook',

  authorizationUrl(state: string, redirectUri: string): string {
    const { appId } = metaAppCredentials()
    const url = new URL('https://www.facebook.com/v21.0/dialog/oauth')
    url.searchParams.set('client_id', appId)
    url.searchParams.set('redirect_uri', redirectUri)
    url.searchParams.set('state', state)
    url.searchParams.set('scope', SCOPES.join(','))
    url.searchParams.set('response_type', 'code')
    return url.toString()
  },

  async exchange(code: string, redirectUri: string): Promise<DiscoveredAccount[]> {
    const { appId, appSecret } = metaAppCredentials()

    const short = new URL(`${GRAPH}/oauth/access_token`)
    short.searchParams.set('client_id', appId)
    short.searchParams.set('client_secret', appSecret)
    short.searchParams.set('redirect_uri', redirectUri)
    short.searchParams.set('code', code)
    const shortToken = String((await graph(short.toString())).access_token ?? '')
    if (!shortToken) throw new Error('Meta returned no access token')

    const long = new URL(`${GRAPH}/oauth/access_token`)
    long.searchParams.set('grant_type', 'fb_exchange_token')
    long.searchParams.set('client_id', appId)
    long.searchParams.set('client_secret', appSecret)
    long.searchParams.set('fb_exchange_token', shortToken)
    const longBody = await graph(long.toString())
    const userToken = String(longBody.access_token ?? '')
    if (!userToken) throw new Error('Meta returned no long-lived token')

    // expires_in is seconds from now, and Meta omits it for tokens that do not
    // expire. Absent means "no known expiry", not "expires immediately".
    const expiresIn = Number(longBody.expires_in ?? 0)
    const expiresAt = expiresIn > 0 ? new Date(Date.now() + expiresIn * 1000) : null

    const granted = await grantedScopes(userToken)

    const pages = await graph(
      `${GRAPH}/me/accounts?fields=id,name,access_token&access_token=${encodeURIComponent(userToken)}`)
    const data = Array.isArray(pages.data) ? pages.data : []

    return data.flatMap((raw): DiscoveredAccount[] => {
      const page = raw as { id?: string; name?: string; access_token?: string }
      if (!page.id || !page.access_token) return []
      return [{
        providerAccountRef: page.id,
        label: page.name ?? page.id,
        credential: page.access_token,
        expiresAt,
        scopes: granted,
      }]
    })
  },

  async revoke(credential: string, providerAccountRef: string): Promise<void> {
    // DELETE /{id}/permissions revokes the app's access for that account. Best
    // effort by contract: the caller clears local state either way, because a
    // token we can no longer revoke is the one we most want to stop storing.
    await fetch(
      `${GRAPH}/${encodeURIComponent(providerAccountRef)}/permissions`
        + `?access_token=${encodeURIComponent(credential)}`,
      { method: 'DELETE', cache: 'no-store' },
    )
  },
}

/** What the user actually granted, which is not necessarily what was requested. */
async function grantedScopes(userToken: string): Promise<string[]> {
  const body = await graph(
    `${GRAPH}/me/permissions?access_token=${encodeURIComponent(userToken)}`)
  const data = Array.isArray(body.data) ? body.data : []
  return data
    .map((raw) => raw as { permission?: string; status?: string })
    .filter((entry) => entry.status === 'granted' && entry.permission)
    .map((entry) => entry.permission!)
}
