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

beforeEach(() => {
  requested = []
  vi.stubGlobal('fetch', async (input: unknown) => {
    const url = String(input)
    requested.push(url)
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
