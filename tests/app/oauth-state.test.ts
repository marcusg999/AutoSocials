/**
 * The OAuth state parameter: signed, and bound to a cookie.
 *
 * Phase 1 deleted its only code-exchange route and left a note saying to bring one
 * back "with a state parameter bound to a cookie when a phase actually introduces
 * OAuth". Both halves are tested here because both are load-bearing and they fail
 * differently:
 *
 *   without a SIGNATURE, anyone can mint a state we accept;
 *   without the COOKIE BINDING, a state we minted for one browser can be replayed
 *   in another — which is how an attacker attaches THEIR social account to the
 *   owner's business.
 */
import { beforeEach, describe, expect, test, vi } from 'vitest'

process.env.CSRF_SIGNING_SECRET ??= 'test-signing-secret-at-least-32-characters-long'

let cookieJar = new Map<string, string>()

vi.mock('next/headers', () => ({
  cookies: async () => ({
    get: (name: string) => (cookieJar.has(name) ? { name, value: cookieJar.get(name)! } : undefined),
    set: (name: string, value: string) => { cookieJar.set(name, value) },
    delete: (name: string) => { cookieJar.delete(name) },
  }),
}))

const { issueOAuthState, consumeOAuthState } = await import('@/lib/connectors/oauth-state')

const BUSINESS = '11111111-1111-4111-8111-111111111111'

beforeEach(() => { cookieJar = new Map() })

test('a state we issued, presented by the browser that got it, verifies', async () => {
  const state = await issueOAuthState({ businessId: BUSINESS, platform: 'facebook' })
  expect(await consumeOAuthState(state)).toEqual({ businessId: BUSINESS, platform: 'facebook' })
})

test('it carries the business, so the callback cannot be aimed at another tenant', async () => {
  const state = await issueOAuthState({ businessId: BUSINESS, platform: 'facebook' })
  const consumed = await consumeOAuthState(state)
  // The callback reads the business from here rather than from a query parameter
  // the caller controls. It still checks membership afterwards — this only stops
  // the value being chosen by the caller.
  expect(consumed?.businessId).toBe(BUSINESS)
})

describe('a state that is not ours, or not this browser\'s, is refused', () => {
  test('a made-up state is rejected', async () => {
    await issueOAuthState({ businessId: BUSINESS, platform: 'facebook' })
    expect(await consumeOAuthState('nonce.9999999999999.b.facebook.signature')).toBeNull()
  })

  test('a state with a tampered payload is rejected even though we signed the original', async () => {
    const state = await issueOAuthState({ businessId: BUSINESS, platform: 'facebook' })
    const parts = state.split('.')
    parts[2] = '22222222-2222-4222-8222-222222222222'
    expect(await consumeOAuthState(parts.join('.'))).toBeNull()
  })

  test('a state we issued to a DIFFERENT browser is rejected', async () => {
    const theirs = await issueOAuthState({ businessId: BUSINESS, platform: 'facebook' })
    // A different browser: no cookie of its own, but it presents a genuine,
    // correctly signed state. The signature proves we minted it; the cookie is
    // what proves we minted it for THIS caller.
    cookieJar = new Map()
    expect(await consumeOAuthState(theirs)).toBeNull()
  })

  test('a state is single use, so a captured callback URL cannot be replayed', async () => {
    const state = await issueOAuthState({ businessId: BUSINESS, platform: 'facebook' })
    expect(await consumeOAuthState(state)).not.toBeNull()
    expect(await consumeOAuthState(state)).toBeNull()
  })

  test('an expired state is rejected', async () => {
    const state = await issueOAuthState({ businessId: BUSINESS, platform: 'facebook' })
    vi.setSystemTime(new Date(Date.now() + 1000 * 60 * 11))
    expect(await consumeOAuthState(state)).toBeNull()
    vi.useRealTimers()
  })

  test('a missing state is rejected rather than treated as absent-and-fine', async () => {
    await issueOAuthState({ businessId: BUSINESS, platform: 'facebook' })
    expect(await consumeOAuthState(null)).toBeNull()
  })
})
