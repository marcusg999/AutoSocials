/**
 * The Meta exchange: which id ends up on the row, and which token.
 *
 * Facebook and Instagram share one OAuth exchange and one credential, which makes
 * it easy to give them one connector — and that is exactly the bug this file
 * exists to prevent. A Facebook Page is addressed by the Page id. An Instagram
 * business account is addressed by ITS OWN id, which only the Page can tell you.
 * Store the Page id on an Instagram row and the connect looks perfectly successful
 * while pointing at an account that cannot be published to.
 *
 * The other property here is negative and just as load-bearing: the long-lived
 * USER token is used during the exchange and must never leave it. Only per-Page
 * tokens are stored, so a leak costs one account rather than every account the
 * person can reach.
 */
import { beforeEach, describe, expect, test, vi } from 'vitest'

vi.mock('@/lib/env', () => ({
  metaAppCredentials: () => ({ appId: 'test-app-id', appSecret: 'test-app-secret' }),
}))

const { facebookConnector, instagramConnector } = await import('@/lib/connectors/meta')

const USER_TOKEN = 'LONG-LIVED-USER-TOKEN-never-store-me'
const PAGE_ONE_TOKEN = 'page-one-token'
const PAGE_TWO_TOKEN = 'page-two-token'

/** Every URL the connectors requested, in order, for the negative assertions. */
let requested: string[] = []

/**
 * A stand-in for the Graph API. Routed by path rather than by call order, because
 * the Instagram exchange makes one extra request per Page and asserting on order
 * would then be asserting on the number of Pages.
 */
function respond(url: string): Record<string, unknown> {
  if (url.includes('/oauth/access_token') && url.includes('code=')) {
    return { access_token: 'short-lived-token', expires_in: 3600 }
  }
  if (url.includes('/oauth/access_token') && url.includes('fb_exchange_token')) {
    return { access_token: USER_TOKEN, expires_in: 5_184_000 }
  }
  if (url.includes('/me/permissions')) {
    return {
      data: [
        { permission: 'pages_show_list', status: 'granted' },
        { permission: 'instagram_basic', status: 'granted' },
        { permission: 'business_management', status: 'declined' },
      ],
    }
  }
  if (url.includes('/me/accounts')) {
    return {
      data: [
        { id: 'page-1', name: 'First Page', access_token: PAGE_ONE_TOKEN },
        { id: 'page-2', name: 'Second Page', access_token: PAGE_TWO_TOKEN },
        // A Page we were not given a token for is one we cannot act as.
        { id: 'page-3', name: 'Tokenless Page' },
      ],
    }
  }
  // Per-Page Instagram lookup. Only the first Page has an Instagram account.
  if (url.includes('/page-1?') || url.includes('/page-1&')) {
    return { instagram_business_account: { id: 'ig-account-1', username: 'first_page' } }
  }
  if (url.includes('/page-2')) return { id: 'page-2' }
  throw new Error(`unrouted Graph request: ${url}`)
}

/** Every POST the connectors made, so the ORDER of the Instagram calls is testable. */
interface Sent { url: string; method: string; params: URLSearchParams }
let sent: Sent[] = []

/** Publish responses, keyed by the path fragment that identifies the edge. */
let publishResponses: Record<string, () => Record<string, unknown>> = {}

beforeEach(() => {
  requested = []
  sent = []
  publishResponses = {
    '/feed': () => ({ id: 'page-1_111' }),
    '/photos': () => ({ id: 'photo-1', post_id: 'page-1_222' }),
    '/media': () => ({ id: 'container-1' }),
    '/media_publish': () => ({ id: 'ig-media-1' }),
  }
  vi.stubGlobal('fetch', async (input: unknown, init?: RequestInit) => {
    const url = String(input)
    requested.push(url)
    const method = init?.method ?? 'GET'
    if (method === 'POST') {
      const params = new URLSearchParams(String(init?.body ?? ''))
      sent.push({ url, method, params })
      // Longest match first, so '/media_publish' is not answered by '/media'.
      const edge = Object.keys(publishResponses)
        .sort((a, b) => b.length - a.length)
        .find((key) => url.includes(key))
      if (!edge) throw new Error(`unrouted POST: ${url}`)
      return { ok: true, json: async () => publishResponses[edge]!() } as unknown as Response
    }
    return { ok: true, json: async () => respond(url) } as unknown as Response
  })
})

describe('the Facebook connector', () => {
  test('returns one account per Page, keyed by the Page id', async () => {
    const accounts = await facebookConnector.exchange('code', 'https://app.example/cb')

    expect(accounts.map((a) => a.providerAccountRef)).toEqual(['page-1', 'page-2'])
    expect(accounts.map((a) => a.credential)).toEqual([PAGE_ONE_TOKEN, PAGE_TWO_TOKEN])
    expect(accounts[0]!.label).toBe('First Page')
  })

  test('records only the scopes Meta says were granted', async () => {
    const [account] = await facebookConnector.exchange('code', 'https://app.example/cb')
    expect(account!.scopes).toEqual(['pages_show_list', 'instagram_basic'])
  })
})

describe('the Instagram connector', () => {
  test('keys the account by the Instagram id, not the Page that owns it', async () => {
    const accounts = await instagramConnector.exchange('code', 'https://app.example/cb')

    expect(accounts).toHaveLength(1)
    expect(accounts[0]!.providerAccountRef).toBe('ig-account-1')
    expect(accounts[0]!.providerAccountRef).not.toBe('page-1')
    expect(accounts[0]!.label).toBe('@first_page')
  })

  test('still carries the PAGE token, because that is what authorises the call', async () => {
    const [account] = await instagramConnector.exchange('code', 'https://app.example/cb')
    expect(account!.credential).toBe(PAGE_ONE_TOKEN)
  })

  test('skips a Page with no Instagram account rather than connecting the Page', async () => {
    const accounts = await instagramConnector.exchange('code', 'https://app.example/cb')
    expect(accounts.map((a) => a.providerAccountRef)).not.toContain('page-2')
  })
})

describe('both connectors', () => {
  test('never return the long-lived user token as a credential', async () => {
    for (const connector of [facebookConnector, instagramConnector]) {
      const accounts = await connector.exchange('code', 'https://app.example/cb')
      expect(accounts.length).toBeGreaterThan(0)
      for (const account of accounts) expect(account.credential).not.toBe(USER_TOKEN)
    }
  })

  test('skip a Page they were given no token for', async () => {
    const accounts = await facebookConnector.exchange('code', 'https://app.example/cb')
    expect(accounts.map((a) => a.providerAccountRef)).not.toContain('page-3')
  })

  test('send the app secret only to the token endpoints', async () => {
    await instagramConnector.exchange('code', 'https://app.example/cb')
    const leaked = requested.filter(
      (url) => url.includes('test-app-secret') && !url.includes('/oauth/access_token'))
    expect(leaked).toEqual([])
  })
})

describe('publishing to Facebook', () => {
  test('a text post goes to /feed and returns the post id', async () => {
    const ref = await facebookConnector.publish(PAGE_ONE_TOKEN, 'page-1', {
      text: 'hello world', imageUrl: null,
    })

    expect(ref).toBe('page-1_111')
    expect(sent).toHaveLength(1)
    expect(sent[0]!.url).toContain('/page-1/feed')
    expect(sent[0]!.params.get('message')).toBe('hello world')
  })

  test('a post with an image goes to /photos, which is a different edge', async () => {
    const ref = await facebookConnector.publish(PAGE_ONE_TOKEN, 'page-1', {
      text: 'caption here', imageUrl: 'https://cdn.example.com/a.jpg',
    })

    expect(sent[0]!.url).toContain('/page-1/photos')
    expect(sent[0]!.params.get('url')).toBe('https://cdn.example.com/a.jpg')
    expect(sent[0]!.params.get('caption')).toBe('caption here')
    // /photos returns both a photo id and the id of the post it created. The post
    // is what a human wants to open.
    expect(ref).toBe('page-1_222')
  })

  test('the token travels in the body, never in the query string', async () => {
    await facebookConnector.publish(PAGE_ONE_TOKEN, 'page-1', { text: 'hi', imageUrl: null })

    expect(sent[0]!.url).not.toContain(PAGE_ONE_TOKEN)
    expect(sent[0]!.params.get('access_token')).toBe(PAGE_ONE_TOKEN)
  })

  test('a provider error becomes a throw, so the attempt is recorded as failed', async () => {
    publishResponses['/feed'] = () => ({ error: { message: 'Page is restricted' } })
    await expect(
      facebookConnector.publish(PAGE_ONE_TOKEN, 'page-1', { text: 'hi', imageUrl: null }),
    ).rejects.toThrow(/Page is restricted/)
  })
})

describe('publishing to Instagram', () => {
  const IMAGE = { text: 'a caption', imageUrl: 'https://cdn.example.com/a.jpg' }

  test('creates a container, then publishes it, in that order', async () => {
    const ref = await instagramConnector.publish(PAGE_ONE_TOKEN, 'ig-account-1', IMAGE)

    expect(sent.map((s) => s.url.split('/').pop())).toEqual(['media', 'media_publish'])
    expect(sent[0]!.params.get('image_url')).toBe('https://cdn.example.com/a.jpg')
    expect(sent[0]!.params.get('caption')).toBe('a caption')
    expect(sent[1]!.params.get('creation_id')).toBe('container-1')
    expect(ref).toBe('ig-media-1')
  })

  /**
   * The safety property of the two-step. Creating a container publishes nothing,
   * so failing there must leave nothing visible and must not have called publish —
   * otherwise a retry could follow a post that already went out.
   */
  test('a failed container never reaches media_publish', async () => {
    publishResponses['/media'] = () => ({ error: { message: 'image could not be fetched' } })

    await expect(instagramConnector.publish(PAGE_ONE_TOKEN, 'ig-account-1', IMAGE))
      .rejects.toThrow(/image could not be fetched/)

    expect(sent.map((s) => s.url)).toHaveLength(1)
    expect(sent[0]!.url).toContain('/media')
    expect(sent.some((s) => s.url.includes('media_publish'))).toBe(false)
  })

  test('a container with no id is an error rather than a publish of nothing', async () => {
    publishResponses['/media'] = () => ({})
    await expect(instagramConnector.publish(PAGE_ONE_TOKEN, 'ig-account-1', IMAGE))
      .rejects.toThrow(/no media container/i)
  })

  test('refuses a text-only post before making any call at all', async () => {
    await expect(
      instagramConnector.publish(PAGE_ONE_TOKEN, 'ig-account-1', { text: 'hi', imageUrl: null }),
    ).rejects.toThrow(/cannot publish text on its own/i)
    expect(sent).toHaveLength(0)
  })

  test('publishes as the Instagram id, not the Page id', async () => {
    await instagramConnector.publish(PAGE_ONE_TOKEN, 'ig-account-1', IMAGE)
    for (const call of sent) {
      expect(call.url).toContain('ig-account-1')
      expect(call.url).not.toContain('/page-1/')
    }
  })
})
