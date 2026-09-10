/**
 * The assistant: what it is told, what it is allowed to do with the answer.
 *
 * The prompt half is ordinary — a wrong instruction produces bad posts, and bad
 * posts are visible before anything is published. The half with a sharp edge is
 * the boundary: this is the one feature in the app that sends the operator's
 * content to a third party and spends money doing it, so what leaves the building
 * is asserted directly rather than assumed from reading the string.
 */
import { beforeEach, describe, expect, test, vi } from 'vitest'

import {
  buildUserMessage, MAX_INSTRUCTION, parseSuggestions, SUGGESTION_COUNT, SYSTEM_PROMPT,
} from '@/lib/assistant/prompt'

const draft = (text: string, imageUrl: string | null = null) => ({ text, imageUrl })

describe('what the assistant is told', () => {
  test('the draft is sent, fenced and labelled', () => {
    const message = buildUserMessage(draft('half a sentence about coffee'), ['facebook'], '')
    expect(message).toContain('<draft>\nhalf a sentence about coffee\n</draft>')
  })

  /**
   * The image is the operator's own URL, and the model cannot fetch it anyway —
   * sending it would be one more place a customer's address ends up for no gain.
   * That an image exists changes what a good caption is, so that part is sent.
   */
  test('an image changes the brief but its address is never sent', () => {
    const message = buildUserMessage(
      draft('look at this', 'https://cdn.example.com/private-path/a.jpg'), ['instagram'], '')

    expect(message).toContain('include an image')
    expect(message).not.toContain('cdn.example.com')
  })

  test('only the platforms actually being posted to are described', () => {
    const facebook = buildUserMessage(draft('hi'), ['facebook'], '')
    expect(facebook).toContain('Facebook')
    expect(facebook).not.toContain('Instagram')

    const both = buildUserMessage(draft('hi'), ['facebook', 'instagram'], '')
    expect(both).toContain('Instagram')
    expect(both).toContain('every platform above')
  })

  test('an empty draft asks for something new rather than sending empty markers', () => {
    const message = buildUserMessage(draft('   '), ['facebook'], 'announce we are open Sundays')
    expect(message).toContain('draft is empty')
    expect(message).not.toContain('<draft>')
    expect(message).toContain('announce we are open Sundays')
  })

  test('a long instruction is bounded rather than sent whole', () => {
    const message = buildUserMessage(draft('hi'), ['facebook'], 'x'.repeat(5000))
    expect(message).not.toContain('x'.repeat(MAX_INSTRUCTION + 1))
  })

  test('the system prompt forbids inventing facts, which is the failure that would post', () => {
    // A made-up price or opening time is the one kind of wrong output that does
    // real damage after a human waves it through.
    expect(SYSTEM_PROMPT).toMatch(/never invent facts/i)
    expect(SYSTEM_PROMPT).toMatch(new RegExp(`exactly ${SUGGESTION_COUNT} alternatives`, 'i'))
  })
})

describe('reading the answer back', () => {
  test('numbered lines become suggestions', () => {
    expect(parseSuggestions('1. first one\n2. second one\n3. third one'))
      .toEqual(['first one', 'second one', 'third one'])
  })

  test('a different numbering style still parses', () => {
    expect(parseSuggestions('1) alpha\n2) beta\n3) gamma')).toEqual(['alpha', 'beta', 'gamma'])
  })

  test('an unnumbered answer is used rather than thrown away', () => {
    // The call has already been paid for. Refusing a usable answer over its
    // formatting spends money and shows the operator an error.
    expect(parseSuggestions('alpha\nbeta')).toEqual(['alpha', 'beta'])
  })

  test('never returns more than it asked for', () => {
    const many = Array.from({ length: 10 }, (_, i) => `${i + 1}. option ${i}`).join('\n')
    expect(parseSuggestions(many)).toHaveLength(SUGGESTION_COUNT)
  })

  test('duplicates are dropped, because three identical options is a choice of one', () => {
    expect(parseSuggestions('1. same\n2. same\n3. different')).toEqual(['same', 'different'])
  })

  test('an empty or whitespace reply yields nothing, so the caller can fail loudly', () => {
    expect(parseSuggestions('')).toEqual([])
    expect(parseSuggestions('\n   \n')).toEqual([])
  })
})

// ---------------------------------------------------------------------------
// The client. The SDK and the key are mocked; what is asserted is the request
// this app makes and what it does with each kind of answer.
// ---------------------------------------------------------------------------

const API_KEY = 'sk-ant-THIS-MUST-NEVER-BE-RECORDED'

let sent: Record<string, unknown>[] = []
let reply: () => unknown

vi.mock('@/lib/env', () => ({
  anthropicApiKey: () => API_KEY,
  isAssistantConfigured: () => true,
}))

class FakeAPIError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}
class FakeAuthError extends FakeAPIError {}
class FakeRateLimitError extends FakeAPIError {}

vi.mock('@anthropic-ai/sdk', () => {
  class Anthropic {
    messages = {
      create: async (params: Record<string, unknown>) => {
        sent.push(params)
        return reply()
      },
    }
    constructor(_options: { apiKey: string }) {}
    static APIError = FakeAPIError
    static AuthenticationError = FakeAuthError
    static RateLimitError = FakeRateLimitError
  }
  return { default: Anthropic }
})

const { ASSISTANT_MODEL, describeAssistantError, suggestPosts } =
  await import('@/lib/assistant/claude')

beforeEach(() => {
  sent = []
  reply = () => ({
    model: ASSISTANT_MODEL,
    stop_reason: 'end_turn',
    content: [{ type: 'text', text: '1. one\n2. two\n3. three' }],
  })
})

describe('the call itself', () => {
  test('asks the pinned model and returns what it said', async () => {
    const suggestions = await suggestPosts(draft('hello'), ['facebook'], '')

    expect(sent).toHaveLength(1)
    expect(sent[0]!.model).toBe(ASSISTANT_MODEL)
    expect(suggestions.map((s) => s.text)).toEqual(['one', 'two', 'three'])
  })

  /**
   * The model id is recorded per suggestion so that "why did it start writing
   * like that" has an answer later. Taking it from the RESPONSE rather than from
   * our own constant means the row says what actually served the request.
   */
  test('records the model the response came back as, not the one we asked for', async () => {
    reply = () => ({
      model: 'claude-something-else',
      stop_reason: 'end_turn',
      content: [{ type: 'text', text: '1. one' }],
    })

    const [suggestion] = await suggestPosts(draft('hello'), ['facebook'], '')
    expect(suggestion!.model).toBe('claude-something-else')
  })

  test('sends the draft and nothing about the app around it', async () => {
    const everything = JSON.stringify(await (async () => {
      await suggestPosts(draft('our new blend', 'https://cdn.example.com/x.jpg'), ['facebook'], '')
      return sent
    })())

    expect(everything).toContain('our new blend')
    // The key travels in a header the SDK sets, never in the message body.
    expect(everything).not.toContain(API_KEY)
    expect(everything).not.toContain('cdn.example.com')
  })

  test('a safety decline is an error, not an empty success', async () => {
    // It arrives as a normal 200. Reading content without checking stop_reason
    // would store nothing and look like the feature silently did nothing.
    reply = () => ({ model: ASSISTANT_MODEL, stop_reason: 'refusal', content: [] })

    await expect(suggestPosts(draft('hello'), ['facebook'], '')).rejects.toThrow(/declined/i)
  })

  test('an answer with no usable text is an error rather than an empty suggestion', async () => {
    reply = () => ({ model: ASSISTANT_MODEL, stop_reason: 'end_turn', content: [] })
    await expect(suggestPosts(draft('hello'), ['facebook'], '')).rejects.toThrow(/nothing usable/i)
  })

  test('ignores non-text blocks instead of crashing on them', async () => {
    reply = () => ({
      model: ASSISTANT_MODEL,
      stop_reason: 'end_turn',
      content: [{ type: 'thinking', thinking: '' }, { type: 'text', text: '1. hello' }],
    })

    expect((await suggestPosts(draft('hi'), ['facebook'], '')).map((s) => s.text)).toEqual(['hello'])
  })
})

describe('describing a failure to the operator', () => {
  /**
   * The asymmetric one, and the same rule as the publisher's last_error: an auth
   * failure is exactly the error most likely to quote back the credential that
   * was rejected, and this text is shown on screen.
   */
  test('never repeats the provider message for an auth failure', () => {
    const message = describeAssistantError(
      new FakeAuthError(401, `invalid x-api-key: ${API_KEY}`))

    expect(message).not.toContain(API_KEY)
    expect(message).toMatch(/ANTHROPIC_API_KEY/)
  })

  test('says what a rate limit is, because it is the one worth retrying', () => {
    expect(describeAssistantError(new FakeRateLimitError(429, 'slow down')))
      .toMatch(/rate limited/i)
  })

  test('falls back to the status for anything else from the API', () => {
    expect(describeAssistantError(new FakeAPIError(500, 'upstream boom'))).toMatch(/500/)
  })

  test('handles a plain error, and a thrown non-error', () => {
    expect(describeAssistantError(new Error('socket hang up'))).toBe('socket hang up')
    expect(describeAssistantError('a string')).toMatch(/assistant failed/i)
  })
})
