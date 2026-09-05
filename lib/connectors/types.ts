/**
 * What every platform connector must provide.
 *
 * Phase 2 is the connector layer only: connecting an account, storing its
 * credential, and disconnecting. Publishing belongs to the scheduler phase and is
 * deliberately absent — Phase 1's brief said not to build ahead, and that held up
 * well enough to repeat.
 *
 * The shape exists so a second platform is one file rather than a second copy of
 * the OAuth plumbing. The credential never appears in this interface's return
 * values by design: it goes straight from the provider exchange into Supabase Vault
 * and is referenced afterwards only by account id.
 */
import type { SocialPlatform } from '@/lib/connectors/platforms'

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
}
