import 'server-only'

import { metaAppCredentials } from '@/lib/env'
import { contentProblemFor, type PostContent } from '@/lib/connectors/content'
import type { Connector, DiscoveredAccount } from '@/lib/connectors/types'

/**
 * The Facebook / Instagram connectors.
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
 *
 * Facebook and Instagram share every one of those exchanges and share the same
 * credential, but they are NOT the same account. A Facebook Page is published to as
 * the Page id; an Instagram business account is published to as its own id, which
 * you can only reach by asking the Page which Instagram account it owns. So they
 * are two connectors over one exchange, and an Instagram row carries the Instagram
 * id — not the Page id that produced its token.
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

/**
 * The same, for calls that change something.
 *
 * Parameters go in the BODY rather than the query string. Meta accepts either, and
 * the query string is the version that ends up in access logs and error reports —
 * which for these calls would mean the Page token, on every publish.
 */
async function graphPost(
  path: string,
  params: Record<string, string>,
): Promise<Record<string, unknown>> {
  const response = await fetch(`${GRAPH}${path}`, {
    method: 'POST',
    cache: 'no-store',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params).toString(),
  })
  const body = (await response.json()) as Record<string, unknown>
  const error = body.error as { message?: string } | undefined
  if (!response.ok || error) {
    throw new Error(`Meta rejected the request: ${error?.message ?? response.status}`)
  }
  return body
}

/** Where to send the browser to begin consent. Identical for both platforms. */
function authorizationUrl(state: string, redirectUri: string): string {
  const { appId } = metaAppCredentials()
  const url = new URL('https://www.facebook.com/v21.0/dialog/oauth')
  url.searchParams.set('client_id', appId)
  url.searchParams.set('redirect_uri', redirectUri)
  url.searchParams.set('state', state)
  url.searchParams.set('scope', SCOPES.join(','))
  url.searchParams.set('response_type', 'code')
  return url.toString()
}

/** One Page the user granted, with the token that acts on its behalf. */
interface PageGrant {
  id: string
  name: string
  token: string
}

/** The shared part of both exchanges: code in, Page tokens out. */
async function exchangeForPages(code: string, redirectUri: string): Promise<{
  pages: PageGrant[]
  expiresAt: Date | null
  scopes: string[]
}> {
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

  const scopes = await grantedScopes(userToken)

  const listing = await graph(
    `${GRAPH}/me/accounts?fields=id,name,access_token&access_token=${encodeURIComponent(userToken)}`)
  const data = Array.isArray(listing.data) ? listing.data : []

  const pages = data.flatMap((raw): PageGrant[] => {
    const page = raw as { id?: string; name?: string; access_token?: string }
    // A Page without a token is one we cannot act for, so it is not an account we
    // can offer to connect. Skipping is right; failing the whole connect is not.
    if (!page.id || !page.access_token) return []
    return [{ id: page.id, name: page.name ?? page.id, token: page.access_token }]
  })

  return { pages, expiresAt, scopes }
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

export const facebookConnector: Connector = {
  platform: 'facebook',

  authorizationUrl,

  async exchange(code: string, redirectUri: string): Promise<DiscoveredAccount[]> {
    const { pages, expiresAt, scopes } = await exchangeForPages(code, redirectUri)
    return pages.map((page) => ({
      providerAccountRef: page.id,
      label: page.name,
      credential: page.token,
      expiresAt,
      scopes,
    }))
  },

  async revoke(credential: string, providerAccountRef: string): Promise<void> {
    // Best effort by contract: the caller clears local state either way, because a
    // token we can no longer revoke is the one we most want to stop storing. This
    // request has never been run against a real Meta app — see BUILD_NOTES.
    await fetch(
      `${GRAPH}/${encodeURIComponent(providerAccountRef)}/permissions`
        + `?access_token=${encodeURIComponent(credential)}`,
      { method: 'DELETE', cache: 'no-store' },
    )
  },

  /**
   * One call, which is why Facebook is the easy half.
   *
   * A post with an image goes to /photos and a post without one goes to /feed;
   * they are different edges rather than one edge with an optional field.
   */
  async publish(
    credential: string,
    providerAccountRef: string,
    content: PostContent,
  ): Promise<string> {
    assertPublishable('facebook', content)
    const page = encodeURIComponent(providerAccountRef)

    if (content.imageUrl) {
      const body = await graphPost(`/${page}/photos`, {
        url: content.imageUrl,
        caption: content.text,
        access_token: credential,
      })
      // /photos returns the photo id AND the id of the post it created. The post is
      // the thing a human wants to open, so prefer it.
      return String(body.post_id ?? body.id ?? '')
    }

    const body = await graphPost(`/${page}/feed`, {
      message: content.text,
      access_token: credential,
    })
    return String(body.id ?? '')
  },
}

export const instagramConnector: Connector = {
  platform: 'instagram',

  authorizationUrl,

  async exchange(code: string, redirectUri: string): Promise<DiscoveredAccount[]> {
    const { pages, expiresAt, scopes } = await exchangeForPages(code, redirectUri)

    const discovered: DiscoveredAccount[] = []
    for (const page of pages) {
      // Instagram business accounts hang off a Page, so this is one lookup per
      // Page. A Page with no Instagram account attached is simply not an Instagram
      // account to connect, and is skipped rather than connected under the wrong id.
      const body = await graph(
        `${GRAPH}/${encodeURIComponent(page.id)}`
          + '?fields=instagram_business_account{id,username}'
          + `&access_token=${encodeURIComponent(page.token)}`)
      const account = body.instagram_business_account as
        { id?: string; username?: string } | undefined
      if (!account?.id) continue

      discovered.push({
        // The Instagram id, not the Page id. Publishing addresses the Instagram
        // account by this id; the Page token is only what authorises the call.
        providerAccountRef: account.id,
        label: account.username ? `@${account.username}` : page.name,
        credential: page.token,
        expiresAt,
        scopes,
      })
    }
    return discovered
  },

  async revoke(credential: string): Promise<void> {
    // Deliberately not `/{instagram-id}/permissions`: permissions belong to the node
    // the token acts as, and this token acts as the Page. With a Page token `/me` IS
    // that Page, so this is the same request the Facebook connector makes, without
    // needing to have stored the Page id alongside the Instagram one. Best effort,
    // and likewise unverified against a real Meta app — see BUILD_NOTES.
    await fetch(
      `${GRAPH}/me/permissions?access_token=${encodeURIComponent(credential)}`,
      { method: 'DELETE', cache: 'no-store' },
    )
  },

  /**
   * Two calls: build a container, then publish it.
   *
   * The order is the whole safety property. Creating a container publishes
   * nothing, so a failure there is free and the attempt can be retried. Only
   * media_publish makes the post visible, and it is the LAST thing that happens —
   * nothing after it can throw, so a retry can never follow a post that already
   * went out. A container that is created and never published simply expires at
   * Meta after 24 hours.
   */
  async publish(
    credential: string,
    providerAccountRef: string,
    content: PostContent,
  ): Promise<string> {
    assertPublishable('instagram', content)
    const account = encodeURIComponent(providerAccountRef)

    // Checked by assertPublishable above; narrowing it here for the type.
    const imageUrl = content.imageUrl!

    const container = await graphPost(`/${account}/media`, {
      image_url: imageUrl,
      caption: content.text,
      access_token: credential,
    })
    const creationId = String(container.id ?? '')
    if (!creationId) throw new Error('Meta created no media container')

    const published = await graphPost(`/${account}/media_publish`, {
      creation_id: creationId,
      access_token: credential,
    })
    return String(published.id ?? '')
  },
}

/**
 * The last fence, not the first.
 *
 * The composer refuses this content and the scheduling action refuses it again;
 * this catches the case where a post was scheduled and then edited into something
 * its platform cannot take. Throwing here costs one failed attempt and a message
 * the operator can read on the calendar.
 */
function assertPublishable(platform: 'facebook' | 'instagram', content: PostContent): void {
  const problem = contentProblemFor(platform, content)
  if (problem) throw new Error(problem)
}
