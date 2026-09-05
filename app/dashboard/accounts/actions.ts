'use server'

import { redirect } from 'next/navigation'
import { revalidatePath } from 'next/cache'

import { assertCsrf } from '@/lib/security/csrf'
import { requireMfaSessionOrThrow } from '@/lib/security/session'
import { recordAuditOrThrow } from '@/lib/audit'
import { UUID_PATTERN } from '@/lib/business'
import { connectorFor, disconnectAccount, oauthRedirectUri } from '@/lib/connectors/service'
import { issueOAuthState } from '@/lib/connectors/oauth-state'
import { isSocialPlatform } from '@/lib/connectors/platforms'

/**
 * Starts a connect flow.
 *
 * This is a server action rather than a GET route so it inherits the guards every
 * other mutation here has: CSRF, an independently established aal2 session, and an
 * audit row written before anything happens. The provider redirect is the last step.
 */
export async function beginConnectAction(formData: FormData): Promise<void> {
  await assertCsrf(formData)
  const { supabase, userId } = await requireMfaSessionOrThrow()

  const businessId = String(formData.get('businessId') ?? '')
  const platform = String(formData.get('platform') ?? '')
  if (!UUID_PATTERN.test(businessId)) throw new Error('Invalid business id')
  if (!isSocialPlatform(platform)) throw new Error('Unknown platform')

  // Row level security makes this the membership check: a non-member gets no row.
  const { data, error } = await supabase
    .from('businesses').select('id').eq('id', businessId).maybeSingle()
  if (error) throw new Error(`Could not verify membership: ${error.message}`)
  if (!data) throw new Error('You are not a member of that business')

  await recordAuditOrThrow({
    action: 'connector.connect.begin',
    businessId,
    targetType: 'business',
    targetId: businessId,
    metadata: { platform },
    actorUserId: userId,
  })

  // The state carries the business, so the callback cannot be pointed at another
  // tenant by editing a query parameter, and is bound to a cookie so it cannot be
  // replayed in a different browser.
  const state = await issueOAuthState({ businessId, platform })
  redirect(connectorFor(platform).authorizationUrl(state, oauthRedirectUri(platform)))
}

/** Disconnects an account: revoke at the provider, clear the secret, mark the row. */
export async function disconnectAccountAction(formData: FormData): Promise<void> {
  await assertCsrf(formData)
  const { supabase, userId } = await requireMfaSessionOrThrow()

  const accountId = String(formData.get('accountId') ?? '')
  if (!UUID_PATTERN.test(accountId)) throw new Error('Invalid account id')

  // RLS again: a non-member reads no row, so this both finds and authorises.
  const { data, error } = await supabase
    .from('social_accounts')
    .select('id, business_id, platform, provider_account_ref')
    .eq('id', accountId)
    .maybeSingle()
  if (error) throw new Error(`Could not read the account: ${error.message}`)
  if (!data) throw new Error('No such account')

  await recordAuditOrThrow({
    action: 'connector.disconnect',
    businessId: data.business_id,
    targetType: 'social_account',
    targetId: accountId,
    metadata: { platform: data.platform },
    actorUserId: userId,
  })

  await disconnectAccount(accountId, data.platform, data.provider_account_ref)
  revalidatePath('/dashboard/accounts')
}
