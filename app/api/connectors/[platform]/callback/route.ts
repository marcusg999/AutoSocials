import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

import { requireMfaSessionOrThrow } from '@/lib/security/session'
import { recordAuditOrThrow } from '@/lib/audit'
import { consumeOAuthState } from '@/lib/connectors/oauth-state'
import { connectorFor, oauthRedirectUri, storeDiscoveredAccounts } from '@/lib/connectors/service'
import { isSocialPlatform } from '@/lib/connectors/platforms'

/**
 * Where the provider sends the authorization code.
 *
 * Phase 1 deleted its only code-exchange route and recorded why: an endpoint that
 * trades a query parameter for a SESSION must sit outside the auth guards, which
 * makes it real attack surface. This route is a different animal and sits INSIDE
 * them — it trades a code for a provider credential, and you must already be signed
 * in with MFA to reach it. That is why it can be guarded like everything else.
 *
 * Three things are checked before any exchange happens:
 *   the caller has a complete aal2 session;
 *   the state verifies against the cookie (so this browser started this flow);
 *   the business in the state is one the caller is actually a member of.
 */
export async function GET(
  request: NextRequest,
  context: { params: Promise<{ platform: string }> },
): Promise<Response> {
  const { supabase, userId } = await requireMfaSessionOrThrow()

  const { platform } = await context.params
  const accounts = new URL('/dashboard/accounts', request.nextUrl.origin)

  if (!isSocialPlatform(platform)) {
    accounts.searchParams.set('error', 'unknown-platform')
    return NextResponse.redirect(accounts)
  }

  // The provider reports a refusal here rather than by failing the exchange.
  if (request.nextUrl.searchParams.get('error')) {
    accounts.searchParams.set('error', 'declined')
    return NextResponse.redirect(accounts)
  }

  // Single use, and cleared whatever the outcome.
  const state = await consumeOAuthState(request.nextUrl.searchParams.get('state'))
  const code = request.nextUrl.searchParams.get('code')
  if (!state || !code || state.platform !== platform) {
    accounts.searchParams.set('error', 'bad-state')
    return NextResponse.redirect(accounts)
  }

  // The state is signed, so the business id in it is ours — but "we issued it" is
  // not "this caller may use it". Row level security answers the second question:
  // a non-member reads no row here.
  const { data: business } = await supabase
    .from('businesses').select('id').eq('id', state.businessId).maybeSingle()
  if (!business) {
    accounts.searchParams.set('error', 'not-a-member')
    return NextResponse.redirect(accounts)
  }

  try {
    const discovered = await connectorFor(platform).exchange(code, oauthRedirectUri(platform))
    const stored = await storeDiscoveredAccounts(state.businessId, platform, discovered)

    await recordAuditOrThrow({
      action: 'connector.connect.completed',
      businessId: state.businessId,
      targetType: 'business',
      targetId: state.businessId,
      // Counts and names only. The credential is not in scope here and must never
      // be: audit_log is append-only, so anything written to it is written forever.
      metadata: { platform, accounts: stored },
      actorUserId: userId,
    })

    accounts.searchParams.set('connected', String(stored))
    return NextResponse.redirect(accounts)
  } catch (error) {
    await recordAuditOrThrow({
      action: 'connector.connect.failed',
      businessId: state.businessId,
      targetType: 'business',
      targetId: state.businessId,
      metadata: { platform, reason: error instanceof Error ? error.message : 'unknown' },
      actorUserId: userId,
    })
    accounts.searchParams.set('error', 'exchange-failed')
    return NextResponse.redirect(accounts)
  }
}
