import 'server-only'

import { createSupabaseAdminClient } from '@/lib/supabase/admin'
import { appOrigin } from '@/lib/env'
import { facebookConnector, instagramConnector } from '@/lib/connectors/meta'
import type { Connector, DiscoveredAccount } from '@/lib/connectors/types'
import type { SocialPlatform } from '@/lib/connectors/platforms'

/**
 * The server-side half of the connector layer.
 *
 * Everything that touches a credential lives here, behind 'server-only', and the
 * credential moves in exactly one direction: provider -> Vault. It is never
 * returned to a caller, never put on a row, and never logged. `social_accounts`
 * holds only the non-secret reference, and reading it back needs the account id,
 * because app.read_account_credential derives the secret name from that id — so
 * the stored reference is not a lookup key even for someone holding it.
 */

const CONNECTORS: Partial<Record<SocialPlatform, Connector>> = {
  // Instagram business accounts are reached through the same Meta app and carry the
  // same Page token, but they are addressed by their own id rather than the Page's,
  // so they get their own connector over the shared exchange.
  facebook: facebookConnector,
  instagram: instagramConnector,
}

export function connectorFor(platform: SocialPlatform): Connector {
  const connector = CONNECTORS[platform]
  if (!connector) throw new Error(`No connector is implemented for ${platform}`)
  return connector
}

/**
 * Derived from APP_ORIGIN, never from a request header.
 *
 * The redirect URI is where the provider sends the authorization code. Building it
 * from a forwarded header would let a caller choose that destination, which is the
 * same class of mistake as trusting a header for the CSRF origin check.
 */
export function oauthRedirectUri(platform: SocialPlatform): string {
  return `${appOrigin()}/api/connectors/${platform}/callback`
}

/**
 * Writes what the provider returned: one row per account, credential into Vault.
 *
 * Returns how many accounts were stored. The credential is deliberately absent
 * from the return type — there is no shape of this function that hands one back.
 */
export async function storeDiscoveredAccounts(
  businessId: string,
  platform: SocialPlatform,
  discovered: DiscoveredAccount[],
): Promise<number> {
  const admin = createSupabaseAdminClient()
  let stored = 0

  for (const account of discovered) {
    // One row per (business, platform, provider account). Reconnecting an account
    // updates it rather than accumulating duplicates the operator has to reconcile.
    const { data: existing } = await admin
      .from('social_accounts')
      .select('id')
      .eq('business_id', businessId)
      .eq('platform', platform)
      .eq('provider_account_ref', account.providerAccountRef)
      .maybeSingle()

    const row = {
      business_id: businessId,
      platform,
      label: account.label,
      provider: 'meta',
      provider_account_ref: account.providerAccountRef,
      status: 'connected' as const,
      connected_at: new Date().toISOString(),
      token_expires_at: account.expiresAt?.toISOString() ?? null,
      scopes: account.scopes,
    }

    const accountId = existing?.id
      ?? (await admin.from('social_accounts').insert(row).select('id').single()).data?.id
    if (!accountId) throw new Error('Could not create the account row')
    if (existing?.id) await admin.from('social_accounts').update(row).eq('id', accountId)

    // The credential goes to Vault under a name derived from the account id. This
    // is the only place it is written, and it is written after the row exists so
    // there is never a secret whose owning row failed to be created.
    const { error } = await admin.schema('app').rpc('store_account_credential', {
      target_account_id: accountId,
      credential: account.credential,
    })
    if (error) throw new Error(`Could not store the credential: ${error.message}`)
    stored += 1
  }

  return stored
}

/**
 * Revokes at the provider, then clears local state.
 *
 * Local state is cleared even if revocation fails: a token we can no longer revoke
 * is exactly the one we most want to stop storing. The provider call is therefore
 * best effort and its failure is not propagated.
 */
export async function disconnectAccount(
  accountId: string,
  platform: SocialPlatform,
  providerAccountRef: string | null,
): Promise<void> {
  const admin = createSupabaseAdminClient()

  try {
    const { data: credential } = await admin.schema('app')
      .rpc('read_account_credential', { target_account_id: accountId })
    if (credential && providerAccountRef) {
      await connectorFor(platform).revoke(String(credential), providerAccountRef)
    }
  } catch {
    // Deliberately swallowed. See the note above.
  }

  await admin.from('social_accounts')
    .update({ status: 'disconnected', connected_at: null, token_expires_at: null, scopes: [] })
    .eq('id', accountId)
  await admin.schema('app').rpc('delete_account_credential', { target_account_id: accountId })
}
