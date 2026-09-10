import 'server-only'

import Anthropic from '@anthropic-ai/sdk'

import { anthropicApiKey } from '@/lib/env'
import type { PostContent } from '@/lib/connectors/content'
import type { SocialPlatform } from '@/lib/connectors/platforms'

import { buildUserMessage, parseSuggestions, SYSTEM_PROMPT } from './prompt'

/**
 * The writing assistant.
 *
 * Marked server-only, like the service-role client: an API key that reached the
 * browser would be a key anyone could spend, and this is the module that holds
 * one. Nothing here is imported by a page or a client component — the composer
 * reaches it through a server action.
 *
 * What the assistant can and cannot do is worth stating plainly, because "AI
 * feature" usually implies more: it reads the draft in front of the operator and
 * returns text. It cannot publish, cannot schedule, cannot read another business's
 * posts, and has no tools. Its entire output is words in a form that a human still
 * has to submit.
 */

/**
 * Pinned rather than "latest". A model change alters what this feature writes, so
 * it should be a commit somebody made on purpose — and the id is recorded on every
 * suggestion, so which model wrote a given line stays answerable later.
 */
export const ASSISTANT_MODEL = 'claude-opus-5'

/**
 * Three short posts. Well under the usual default, for a stated reason: the
 * longest reply this can legitimately need is three posts at Instagram's 2,200
 * character caption limit, and a ceiling above that would only ever pay for
 * something going wrong.
 */
const MAX_TOKENS = 4000

export type Suggestion = { text: string; model: string }

/**
 * Ask for alternatives to a draft.
 *
 * Throws on anything that is not a usable answer, so the caller records a failure
 * the operator can see rather than storing nothing and appearing to succeed.
 */
export async function suggestPosts(
  content: PostContent,
  platforms: SocialPlatform[],
  instruction: string,
): Promise<Suggestion[]> {
  const client = new Anthropic({ apiKey: anthropicApiKey() })

  const response = await client.messages.create({
    model: ASSISTANT_MODEL,
    max_tokens: MAX_TOKENS,
    // Low effort on purpose: rewriting a sentence in somebody's own voice is not
    // a reasoning problem, and effort is the lever that costs money.
    output_config: { effort: 'low' },
    system: SYSTEM_PROMPT,
    messages: [{ role: 'user', content: buildUserMessage(content, platforms, instruction) }],
  })

  // A safety decline arrives as a normal 200 with this stop reason, so reading
  // content without checking would quietly produce nothing.
  if (response.stop_reason === 'refusal') {
    throw new Error('The assistant declined to write this one. Try rewording the draft.')
  }

  const reply = response.content
    .filter((block): block is Anthropic.TextBlock => block.type === 'text')
    .map((block) => block.text)
    .join('\n')

  const suggestions = parseSuggestions(reply)
  if (suggestions.length === 0) {
    throw new Error('The assistant replied with nothing usable')
  }

  return suggestions.map((text) => ({ text, model: response.model }))
}

/**
 * A provider error, made safe to record.
 *
 * The same rule as the publisher's last_error: this text is written into a row the
 * operator reads, and an auth failure is exactly the kind of error that quotes
 * back the key it rejected.
 */
export function describeAssistantError(error: unknown): string {
  if (error instanceof Anthropic.AuthenticationError) {
    return 'The assistant rejected the API key. Check ANTHROPIC_API_KEY.'
  }
  if (error instanceof Anthropic.RateLimitError) {
    return 'The assistant is rate limited. Try again in a minute.'
  }
  if (error instanceof Anthropic.APIError) {
    return `The assistant failed (${error.status ?? 'no status'})`
  }
  return error instanceof Error ? error.message : 'The assistant failed'
}
