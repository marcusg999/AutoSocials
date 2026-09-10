/**
 * What a post actually says, and which platforms will accept it.
 *
 * Deliberately free of server-only imports, like platforms.ts, because the same
 * rules have to hold in three places: the composer that writes the post, the
 * scheduling action that accepts it, and the connector that publishes it. Three
 * copies of "Instagram needs an image" would eventually disagree, and the copy
 * that loses is the one running at 3am with nobody watching.
 */
import type { SocialPlatform } from '@/lib/connectors/platforms'

/** Stored in posts.body. */
export interface PostContent {
  text: string
  /**
   * A publicly reachable image URL. Meta fetches this itself — it is never
   * uploaded through this app — so it must be reachable from the internet, not
   * from localhost.
   */
  imageUrl?: string | null
}

export const MAX_POST_TEXT = 2200

/** Reads posts.body, which is jsonb and therefore anything at all until checked. */
export function parsePostContent(body: unknown): PostContent {
  const record = (body ?? {}) as Record<string, unknown>
  const text = typeof record.text === 'string' ? record.text : ''
  const imageUrl = typeof record.imageUrl === 'string' && record.imageUrl.trim() !== ''
    ? record.imageUrl.trim()
    : null
  return { text, imageUrl }
}

/**
 * Why this content cannot go to this platform, or null if it can.
 *
 * Returns a message for a human rather than a boolean, because the operator has to
 * fix it and "invalid" does not tell them how.
 */
export function contentProblemFor(
  platform: SocialPlatform,
  content: PostContent,
): string | null {
  const text = content.text.trim()

  if (text === '' && !content.imageUrl) {
    return 'A post needs some text, or an image, or both.'
  }
  if (text.length > MAX_POST_TEXT) {
    return `That is ${text.length} characters; the limit is ${MAX_POST_TEXT}.`
  }
  if (content.imageUrl && !isPubliclyFetchableUrl(content.imageUrl)) {
    return 'The image URL must be a public https:// address — Meta fetches it itself.'
  }

  // Instagram has no text-only post. There is no way to work around this at
  // publish time, so it has to be caught while a human is still looking at it:
  // discovering it from a failed row hours later is the whole failure mode this
  // function exists to prevent.
  if (platform === 'instagram' && !content.imageUrl) {
    return 'Instagram cannot publish text on its own. Add an image URL.'
  }

  return null
}

/**
 * https only, and no obvious loopback.
 *
 * This is not a security boundary — the URL is handed to Meta, which fetches it
 * from its own network, so it cannot reach anything of ours. It is a usability
 * one: `http://localhost/x.jpg` is the mistake somebody makes on their first
 * attempt, and it fails at publish time with an opaque provider error.
 */
export function isPubliclyFetchableUrl(candidate: string): boolean {
  let url: URL
  try {
    url = new URL(candidate)
  } catch {
    return false
  }
  if (url.protocol !== 'https:') return false

  const host = url.hostname.toLowerCase()
  if (host === 'localhost' || host.endsWith('.localhost')) return false
  if (host === '127.0.0.1' || host === '::1' || host === '[::1]') return false
  if (host.endsWith('.local')) return false
  return true
}
