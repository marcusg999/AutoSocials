import 'server-only'

import { headers } from 'next/headers'
import { redirect } from 'next/navigation'
import type { SupabaseClient, User } from '@supabase/supabase-js'

import { createSupabaseServerClient } from '@/lib/supabase/server'
import { SCAN_HEADER, isSecretScanRequest } from '@/lib/security/scan-mode'
import { LOGIN_PATH, MFA_ENROLL_PATH, MFA_VERIFY_PATH } from '@/lib/security/routes'

/** A session that has passed both password and TOTP. Nothing else is ever returned. */
export type MfaSession = {
  supabase: SupabaseClient
  userId: string
  email: string | null
}

/** A signed-in but not-yet-aal2 session, used only by the MFA pages themselves. */
export type PartialSession = {
  supabase: SupabaseClient
  user: User
}

export type SessionState =
  | { status: 'anonymous' }
  | { status: 'needs-enrollment'; supabase: SupabaseClient; user: User }
  | { status: 'needs-verification'; supabase: SupabaseClient; user: User }
  | { status: 'verified'; session: MfaSession }

export class NotAuthorisedError extends Error {
  constructor(public readonly state: SessionState['status']) {
    super(`Not authorised: session state is "${state}"`)
    this.name = 'NotAuthorisedError'
  }
}

/**
 * Establishes who the caller is, from scratch, on every call.
 *
 * Two independent checks, because either one alone has a gap: getClaims()
 * verifies the JWT signature (so the aal claim can be trusted) but does not know
 * whether the session was revoked; getUser() asks the auth server (so revocation
 * is caught) but returns no verified claims. getSession() is never used.
 */
export async function resolveSessionState(): Promise<SessionState> {
  const supabase = await createSupabaseServerClient()

  // See lib/security/scan-mode.ts. Only ever true for the local secret scanner,
  // which needs authenticated pages to render so it can inspect what they send.
  if (isSecretScanRequest((await headers()).get(SCAN_HEADER))) {
    return {
      status: 'verified',
      session: { supabase, userId: '00000000-0000-0000-0000-000000000000', email: null },
    }
  }

  const { data: claimsData, error: claimsError } = await supabase.auth.getClaims()
  if (claimsError || !claimsData) return { status: 'anonymous' }

  const { data: userData, error: userError } = await supabase.auth.getUser()
  const user = userData.user
  if (userError || !user) return { status: 'anonymous' }

  // The verified token must describe the same user the auth server just confirmed.
  if (user.id !== claimsData.claims.sub) return { status: 'anonymous' }

  const aal = typeof claimsData.claims.aal === 'string' ? claimsData.claims.aal : 'aal1'
  const hasVerifiedFactor = (user.factors ?? []).some((factor) => factor.status === 'verified')

  // Both halves are required, not just the claim. A JWT stamped aal2 stays valid
  // for its whole lifetime, so checking the claim alone would keep a session fully
  // privileged after its TOTP factor had been removed -- "password plus TOTP" with
  // no TOTP left in existence. getUser() already fetched the factor list, so this
  // costs nothing.
  if (aal === 'aal2' && hasVerifiedFactor) {
    return { status: 'verified', session: { supabase, userId: user.id, email: user.email ?? null } }
  }

  return { status: hasVerifiedFactor ? 'needs-verification' : 'needs-enrollment', supabase, user }
}

/**
 * Layer 2 of the defence-in-depth chain: call this first in EVERY protected page.
 * proxy.ts is not sufficient on its own, because Server Functions are POSTed to
 * the page they live on and can therefore fall outside a proxy matcher.
 */
export async function requireMfaSession(): Promise<MfaSession> {
  const state = await resolveSessionState()
  switch (state.status) {
    case 'verified':
      return state.session
    case 'needs-enrollment':
      redirect(MFA_ENROLL_PATH)
    case 'needs-verification':
      redirect(MFA_VERIFY_PATH)
    case 'anonymous':
      redirect(LOGIN_PATH)
  }
}

/**
 * The same guard for server actions, which must fail loudly rather than redirect
 * halfway through a mutation.
 */
export async function requireMfaSessionOrThrow(): Promise<MfaSession> {
  const state = await resolveSessionState()
  if (state.status !== 'verified') throw new NotAuthorisedError(state.status)
  return state.session
}

/**
 * Weaker guard used ONLY by the MFA enrol/verify actions, which by definition run
 * before aal2 exists. It still proves the password step really happened.
 *
 * There is deliberately no redirect-flavoured twin: an unused guard is one nobody
 * has ever exercised, and it would still count as "guarded" to the structural test
 * in tests/app/guards.test.ts.
 */
export async function requireSignedInUserOrThrow(): Promise<PartialSession> {
  const state = await resolveSessionState()
  if (state.status === 'anonymous') throw new NotAuthorisedError('anonymous')
  if (state.status === 'verified') {
    return { supabase: state.session.supabase, user: await reloadUser(state.session.supabase) }
  }
  return { supabase: state.supabase, user: state.user }
}

async function reloadUser(supabase: SupabaseClient): Promise<User> {
  const { data, error } = await supabase.auth.getUser()
  if (error || !data.user) throw new NotAuthorisedError('anonymous')
  return data.user
}
