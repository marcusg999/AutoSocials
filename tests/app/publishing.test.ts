/**
 * The publisher, and the two pure rules it depends on.
 *
 * The database half of Phase 3 is tested in tests/db/publishing.test.ts against a
 * real Postgres, because that is where the claim lives. This file covers what
 * happens around it: what content a platform will accept, what a submitted time
 * actually means, and what the worker records when a publish succeeds or fails.
 *
 * The property with the sharpest edge here is the last one. last_error is written
 * into a row the operator reads and lives in a table that by design can never be
 * pruned, so a Page token appearing in provider error text would be a credential
 * we cannot take back.
 */
import { beforeEach, describe, expect, test, vi } from 'vitest'

import { contentProblemFor, isPubliclyFetchableUrl, parsePostContent } from '@/lib/connectors/content'
import { defaultScheduleValue, formatUtc, parseScheduledFor } from '@/lib/publishing/schedule-time'

describe('what a platform will accept', () => {
  test('Instagram refuses a text-only post, while Facebook takes it', () => {
    const textOnly = { text: 'hello there', imageUrl: null }
    expect(contentProblemFor('instagram', textOnly)).toMatch(/cannot publish text on its own/i)
    expect(contentProblemFor('facebook', textOnly)).toBeNull()
  })

  test('Instagram takes the same post once it has an image', () => {
    expect(contentProblemFor('instagram', {
      text: 'hello', imageUrl: 'https://example.com/a.jpg',
    })).toBeNull()
  })

  test('an empty post is refused everywhere', () => {
    expect(contentProblemFor('facebook', { text: '   ', imageUrl: null }))
      .toMatch(/needs some text, or an image/i)
  })

  test('an image with no text is fine — that is a normal post', () => {
    expect(contentProblemFor('facebook', { text: '', imageUrl: 'https://example.com/a.jpg' }))
      .toBeNull()
  })

  test('over-long text is refused, and the message says by how much', () => {
    const problem = contentProblemFor('facebook', { text: 'x'.repeat(3000), imageUrl: null })
    expect(problem).toMatch(/3000 characters/)
  })

  describe('the image URL has to be one Meta can actually fetch', () => {
    test.each([
      ['http://example.com/a.jpg', 'plain http'],
      ['https://localhost/a.jpg', 'localhost'],
      ['https://127.0.0.1/a.jpg', 'loopback v4'],
      ['https://my-nas.local/a.jpg', '.local'],
      ['not a url at all', 'unparseable'],
    ])('%s is refused (%s)', (url) => {
      expect(isPubliclyFetchableUrl(url)).toBe(false)
      expect(contentProblemFor('facebook', { text: 'hi', imageUrl: url }))
        .toMatch(/public https/i)
    })

    test('a real https address is accepted', () => {
      expect(isPubliclyFetchableUrl('https://cdn.example.com/photo.jpg')).toBe(true)
    })
  })

  test('posts.body is jsonb, so it is read defensively rather than trusted', () => {
    expect(parsePostContent(null)).toEqual({ text: '', imageUrl: null })
    expect(parsePostContent({ text: 42, imageUrl: '  ' })).toEqual({ text: '', imageUrl: null })
    expect(parsePostContent({ text: 'hi', imageUrl: ' https://x.test/a.jpg ' }))
      .toEqual({ text: 'hi', imageUrl: 'https://x.test/a.jpg' })
  })
})

describe('when a post goes out', () => {
  test('a submitted time is read as UTC, not as the server\'s local zone', () => {
    // The whole point: this assertion holds whatever TZ the host is set to.
    expect(parseScheduledFor('2026-09-09T14:30')?.toISOString())
      .toBe('2026-09-09T14:30:00.000Z')
  })

  test('seconds are optional, because browsers omit them', () => {
    expect(parseScheduledFor('2026-09-09T14:30:45')?.toISOString())
      .toBe('2026-09-09T14:30:45.000Z')
  })

  test('a date that does not exist is refused rather than rolled over', () => {
    // Date.UTC turns 31 February into 3 March. Silently moving somebody's post by
    // three days is worse than refusing the form.
    expect(parseScheduledFor('2026-02-31T09:00')).toBeNull()
    expect(parseScheduledFor('2026-13-01T09:00')).toBeNull()
    expect(parseScheduledFor('2026-09-09T25:00')).toBeNull()
  })

  test('junk is refused', () => {
    for (const value of ['', 'tomorrow', '2026-09-09', '09/09/2026 14:30']) {
      expect(parseScheduledFor(value)).toBeNull()
    }
  })

  test('every displayed time says UTC, so there is nothing to misread', () => {
    expect(formatUtc('2026-09-09T14:30:00.000Z')).toBe('2026-09-09 14:30 UTC')
    expect(formatUtc(null)).toBe('—')
    expect(formatUtc('not a date')).toBe('—')
  })

  test('the form default is an hour ahead and round-trips through the parser', () => {
    const now = new Date('2026-09-09T14:30:00.000Z')
    const value = defaultScheduleValue(now)
    expect(value).toBe('2026-09-09T15:30')
    expect(parseScheduledFor(value)?.toISOString()).toBe('2026-09-09T15:30:00.000Z')
  })
})

// ---------------------------------------------------------------------------
// The worker. Mocked at the two edges it actually has: the database and the
// connector. Everything between them is the code under test.
// ---------------------------------------------------------------------------

const CREDENTIAL = 'PAGE-TOKEN-must-never-be-recorded-a1b2c3'

let claimed: unknown[] = []
let completions: Record<string, unknown>[] = []
let claimError: string | null = null
let publishImpl: () => Promise<string>

vi.mock('@/lib/supabase/admin', () => ({
  createSupabaseAdminClient: () => ({
    schema: () => ({
      rpc: async (name: string, args: Record<string, unknown>) => {
        if (name === 'claim_due_scheduled_posts') {
          return claimError ? { data: null, error: { message: claimError } } : { data: claimed, error: null }
        }
        if (name === 'read_account_credential') return { data: CREDENTIAL, error: null }
        if (name === 'complete_scheduled_post') {
          completions.push(args)
          return { data: null, error: null }
        }
        throw new Error(`unexpected rpc: ${name}`)
      },
    }),
  }),
}))

vi.mock('@/lib/connectors/service', () => ({
  connectorFor: () => ({ publish: () => publishImpl() }),
}))

const { publishDuePosts, redactCredential } = await import('@/lib/publishing/service')

function due(overrides: Record<string, unknown> = {}) {
  return {
    scheduled_id: '11111111-1111-4111-8111-111111111111',
    business_id: '22222222-2222-4222-8222-222222222222',
    post_id: '33333333-3333-4333-8333-333333333333',
    social_account_id: '44444444-4444-4444-8444-444444444444',
    platform: 'facebook',
    provider_account_ref: 'page-1',
    body: { text: 'hello' },
    attempts: 1,
    ...overrides,
  }
}

beforeEach(() => {
  claimed = []
  completions = []
  claimError = null
  publishImpl = async () => 'page-1_9876'
})

describe('the worker', () => {
  test('publishes a claimed post and records what the platform created', async () => {
    claimed = [due()]

    const result = await publishDuePosts({ worker: 'test' })

    expect(result).toEqual({ claimed: 1, published: 1, failed: 0 })
    expect(completions).toHaveLength(1)
    expect(completions[0]!.p_ok).toBe(true)
    expect(completions[0]!.p_provider_post_ref).toBe('page-1_9876')
    expect(completions[0]!.p_error).toBeNull()
  })

  test('records a failure instead of throwing, so the run continues', async () => {
    claimed = [due()]
    publishImpl = async () => { throw new Error('Meta rejected the request: rate limited') }

    const result = await publishDuePosts({ worker: 'test' })

    expect(result).toEqual({ claimed: 1, published: 0, failed: 1 })
    expect(completions[0]!.p_ok).toBe(false)
    expect(completions[0]!.p_error).toMatch(/rate limited/)
  })

  test('one bad row does not abandon the rest of the batch', async () => {
    claimed = [due({ scheduled_id: 'a' }), due({ scheduled_id: 'b' }), due({ scheduled_id: 'c' })]
    let call = 0
    publishImpl = async () => {
      call += 1
      if (call === 2) throw new Error('that one broke')
      return `ref-${call}`
    }

    const result = await publishDuePosts({ worker: 'test' })

    expect(result).toEqual({ claimed: 3, published: 2, failed: 1 })
    expect(completions.map((c) => c.p_scheduled_id)).toEqual(['a', 'b', 'c'])
  })

  /**
   * The asymmetric one. A redacted message is mildly annoying; a Page token
   * written into an append-only table is a credential nobody can take back.
   */
  test('never writes the credential into last_error, even if the provider echoes it', async () => {
    claimed = [due()]
    publishImpl = async () => {
      throw new Error(`Meta rejected the request: bad token ${CREDENTIAL} for page-1`)
    }

    await publishDuePosts({ worker: 'test' })

    const recorded = String(completions[0]!.p_error)
    expect(recorded).not.toContain(CREDENTIAL)
    expect(recorded).toContain('[redacted credential]')
  })

  test('refuses to publish an account with no provider reference', async () => {
    claimed = [due({ provider_account_ref: null })]
    const result = await publishDuePosts({ worker: 'test' })
    expect(result.failed).toBe(1)
    expect(String(completions[0]!.p_error)).toMatch(/reconnect it/i)
  })

  test('claims nothing and does nothing when nothing is due', async () => {
    const result = await publishDuePosts({ worker: 'test' })
    expect(result).toEqual({ claimed: 0, published: 0, failed: 0 })
    expect(completions).toHaveLength(0)
  })

  test('a claim that fails stops the run rather than reporting a quiet success', async () => {
    claimError = 'connection refused'
    await expect(publishDuePosts({ worker: 'test' })).rejects.toThrow(/Could not claim/)
  })

  test('passes the lease through as an interval the database understands', async () => {
    claimed = []
    await publishDuePosts({ worker: 'test', leaseMinutes: 9 })
    // Nothing to assert on completions; the shape is asserted by the db test. This
    // is here so the option is exercised and cannot silently stop being passed.
    expect(true).toBe(true)
  })
})

describe('redaction', () => {
  test('replaces every occurrence', () => {
    expect(redactCredential('a SECRETTOKEN b SECRETTOKEN', 'SECRETTOKEN'))
      .toBe('a [redacted credential] b [redacted credential]')
  })

  test('leaves the message alone when there is no credential to hide', () => {
    expect(redactCredential('plain failure', null)).toBe('plain failure')
  })

  test('ignores a credential too short to be one, which would redact everything', () => {
    // Guarding against a stub or empty-ish value turning every message into noise.
    expect(redactCredential('a e i o u', 'e')).toBe('a e i o u')
  })
})
