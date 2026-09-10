/**
 * What the assistant is asked, and how its answer is read back.
 *
 * Deliberately pure and free of the API client, so the two things most likely to
 * be wrong — what we send, and how we interpret what comes back — can be tested
 * without a network call or an API key.
 *
 * The prompt is in the source tree rather than in the database on purpose: it is
 * reviewable in a diff, it changes with the code that depends on it, and it never
 * needs to be copied into every suggestion row.
 */
import type { SocialPlatform } from '@/lib/connectors/platforms'
import { MAX_POST_TEXT, type PostContent } from '@/lib/connectors/content'

/** How many alternatives to ask for. Enough to choose between, few enough to read. */
export const SUGGESTION_COUNT = 3

/** A steer from the operator ("shorter", "less formal"). Bounded because it is free text. */
export const MAX_INSTRUCTION = 500

export const SYSTEM_PROMPT = [
  'You write social media posts for a small business.',
  '',
  'Rules:',
  `- Reply with exactly ${SUGGESTION_COUNT} alternatives, each on its own line, numbered "1." to "${SUGGESTION_COUNT}.".`,
  '- No preamble, no commentary, no closing remark. Only the numbered lines.',
  '- Each alternative must be a complete post, ready to publish as written.',
  '- Keep the business\'s own voice. You are editing their draft, not replacing it.',
  '- Never invent facts: no prices, dates, opening hours, discounts or claims that',
  '  are not already in the draft. If the draft is vague, stay vague.',
  '- No hashtag spam. At most two, and only if they are obviously right.',
  '- Write plain text. No markdown, no bold, no bullet characters.',
].join('\n')

/**
 * The platform rules worth telling the model about — the ones that change what a
 * good post looks like, not every detail of the API.
 */
function platformNotes(platforms: SocialPlatform[]): string[] {
  const notes: string[] = []
  if (platforms.includes('instagram')) {
    notes.push('- Instagram: a caption under an image. Front-load the interesting part.')
  }
  if (platforms.includes('facebook')) {
    notes.push('- Facebook: a little more room, and links are fine.')
  }
  if (platforms.length > 1) {
    notes.push('- The same text goes to every platform above, so it has to work for all of them.')
  }
  return notes
}

/**
 * The message the model actually receives.
 *
 * The draft is the operator's own text, so there is no untrusted party here — but
 * it is still fenced and labelled, so a draft that happens to contain something
 * like an instruction reads as content rather than as a new rule.
 */
export function buildUserMessage(
  content: PostContent,
  platforms: SocialPlatform[],
  instruction: string,
): string {
  const parts: string[] = []

  const draft = content.text.trim()
  parts.push(draft === ''
    ? 'The draft is empty. Write something from the details below.'
    : `Here is the draft, between the markers:\n<draft>\n${draft}\n</draft>`)

  if (content.imageUrl) {
    // The address itself is not useful to the model and is not sent; that it
    // exists changes what a good caption looks like, and that is.
    parts.push('The post will include an image.')
  }

  const notes = platformNotes(platforms)
  if (notes.length > 0) parts.push(`Where it is going:\n${notes.join('\n')}`)

  const steer = instruction.trim().slice(0, MAX_INSTRUCTION)
  if (steer !== '') parts.push(`What they asked for:\n<instruction>\n${steer}\n</instruction>`)

  parts.push(`Each alternative must be at most ${MAX_POST_TEXT} characters.`)
  parts.push(`Reply with ${SUGGESTION_COUNT} numbered alternatives and nothing else.`)

  return parts.join('\n\n')
}

/**
 * Reads the numbered lines back out.
 *
 * Written to be forgiving about shape and strict about emptiness: a model that
 * answers in a slightly different format should still be usable, but storing a
 * blank "suggestion" would put an empty row in front of the operator and look
 * like the feature is broken.
 */
export function parseSuggestions(reply: string): string[] {
  const lines = reply.split('\n').map((line) => line.trim()).filter((line) => line !== '')

  const numbered = lines
    .filter((line) => /^\d+[.)]\s*/.test(line))
    .map((line) => line.replace(/^\d+[.)]\s*/, '').trim())

  // Falling back to every non-empty line rather than to nothing: an unnumbered
  // answer is still three usable posts, and refusing it would spend the call and
  // show the operator an error.
  const candidates = numbered.length > 0 ? numbered : lines

  const seen = new Set<string>()
  return candidates
    .filter((text) => text !== '')
    .filter((text) => {
      if (seen.has(text)) return false
      seen.add(text)
      return true
    })
    .slice(0, SUGGESTION_COUNT)
}
