'use server'

import { redirect } from 'next/navigation'

import { assertCsrf, rotateCsrfToken } from '@/lib/security/csrf'
import { createSupabaseServerClient } from '@/lib/supabase/server'
import { recordAnonymousAudit, recordAuditOrThrow } from '@/lib/audit'
import {
  DASHBOARD_PATH,
  LOGIN_PATH,
  MFA_ENROLL_PATH,
  MFA_VERIFY_PATH,
} from '@/lib/security/routes'

export async function signInAction(formData: FormData): Promise<void> {
  // Layer 2 for this action: a mutation is never accepted on the proxy's word alone.
  await assertCsrf(formData)

  // Capped at the RFC maximum. The failed-login path writes this into an
  // append-only table that nothing can prune, so an unbounded value from an
  // unauthenticated caller is a permanent, attacker-controlled write primitive.
  const email = String(formData.get('email') ?? '').trim().slice(0, 320)
  const password = String(formData.get('password') ?? '')
  if (!email || !password) redirect(`${LOGIN_PATH}?error=missing`)

  const supabase = await createSupabaseServerClient()

  // Written before the attempt, not after. signInWithPassword() writes session
  // cookies; if the audit row were only written afterwards and that write failed,
  // the user would be signed in with no record of it -- the single event most
  // worth having. Recording the attempt first means the trail can never be
  // silently shorter than reality.
  await recordAuditOrThrow({ action: 'auth.login.attempt', metadata: { email } })

  const { error } = await supabase.auth.signInWithPassword({ email, password })

  if (error) {
    // No session exists, so this row has a null actor. The attempted address is
    // kept deliberately: without it a burst of failures cannot be told apart from
    // credential stuffing. It is the one piece of personal data in an append-only
    // table, and is noted as such in BUILD_NOTES.md.
    await recordAnonymousAudit({
      action: 'auth.login.failure',
      metadata: { email, reason: error.message },
    })
    // Deliberately vague: the page must not reveal whether the address exists.
    redirect(`${LOGIN_PATH}?error=invalid`)
  }

  // A new session gets a new CSRF token, so one minted before sign-in -- possibly
  // by somebody else -- can never be replayed across the boundary.
  // The user id comes from the session we just established, not from the form.
  const { data: signedIn } = await supabase.auth.getUser()

  // The new token is bound to the new user, so the pre-login one cannot cross the
  // session boundary.
  await rotateCsrfToken(signedIn.user?.id ?? null)
  await recordAuditOrThrow({ action: 'auth.login.success', actorUserId: signedIn.user?.id ?? null })

  // A password is only the first factor; where to go next depends on MFA state.
  const { data: aal } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel()
  if (aal?.currentLevel === 'aal2') redirect(DASHBOARD_PATH)
  redirect(aal?.nextLevel === 'aal2' ? MFA_VERIFY_PATH : MFA_ENROLL_PATH)
}
