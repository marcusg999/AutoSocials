/**
 * What every platform connector must provide.
 *
 * Phase 2 built connecting, storing a credential and disconnecting. Phase 3 adds
 * exactly one thing to this interface — publish — because that is what a scheduler
 * needs and nothing more.
 *
 * The shape exists so a second platform is one file rather than a second copy of
 * the OAuth plumbing. The credential never appears in this interface's return
 * values by design: it goes straight from the provider exchange into Supabase Vault
 * and is referenced afterwards only by account id.
 */
import type { SocialPlatform } from '@/lib/connectors/platforms'
import type { PostContent } from '@/lib/connectors/content'

/** One account the provider says we may manage, before the user picks any. */
export interface DiscoveredAccount {
  /** The provider's own id — a Facebook Page id, an Instagram business account id. */
  providerAccountRef: string
  /** What to show the human. */
  label: string
  /** The per-account credential. Written to Vault, never returned to a browser. */
  credential: string
  /** When the credential stops working, if the provider says. */
  expiresAt: Date | null
  /** What the user actually granted, which can be fewer than what was asked for. */
  scopes: string[]
}

export interface Connector {
  readonly platform: SocialPlatform

  /** Where to send the browser to begin consent. `state` is opaque to the provider. */
  authorizationUrl(state: string, redirectUri: string): string

  /**
   * Trade the one-time code for durable credentials and list what it can manage.
   *
   * Throws on any provider error rather than returning a partial result: a
   * half-connected account that looks connected is worse than a failed connect.
   */
  exchange(code: string, redirectUri: string): Promise<DiscoveredAccount[]>

  /**
   * Best-effort revocation at the provider. Local state is cleared regardless of
   * the outcome — a token we can no longer revoke is exactly the one we most want
   * to stop storing.
   */
  revoke(credential: string, providerAccountRef: string): Promise<void>

  /**
   * Publish once, and return the platform's own id for what was created.
   *
   * Throws on any failure. The caller treats a throw as "this attempt failed" and
   * will retry, so an implementation must not throw after the post is actually
   * live — that turns one published post into two. Where a platform needs several
   * calls, the LAST one is the one that publishes, and anything after it must not
   * be able to fail the attempt.
   *
   * The returned reference is stored so the operator can go and find the post. It
   * is not used to address the post again; nothing here edits or deletes.
   */
  publish(
    credential: string,
    providerAccountRef: string,
    content: PostContent,
  ): Promise<string>
}
