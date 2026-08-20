'use server'

import { redirect } from 'next/navigation'

import { assertCsrf } from '@/lib/security/csrf'
import { createSupabaseServerClient } from '@/lib/supabase/server'
import { recordAnonymousAudit, recordAudit } from '@/lib/audit'
import {
  DASHBOARD_PATH,
  LOGIN_PATH,
  MFA_ENROLL_PATH,
  MFA_VERIFY_PATH,
} from '@/lib/security/routes'

export async function signInAction(formData: FormData): Promise<void> {
  // Layer 2 for this action: a mutation is never accepted on the proxy's word alone.
  await assertCsrf(formData)

  const email = String(formData.get('email') ?? '').trim()
  const password = String(formData.get('password') ?? '')
  if (!email || !password) redirect(`${LOGIN_PATH}?error=missing`)

  const supabase = await createSupabaseServerClient()
  const { error } = await supabase.auth.signInWithPassword({ email, password })

  if (error) {
    // Written with the service role client because there is no session to write under.
    await recordAnonymousAudit({
      action: 'auth.login.failure',
      metadata: { email, reason: error.message },
    })
    // Deliberately vague: the page must not reveal whether the address exists.
    redirect(`${LOGIN_PATH}?error=invalid`)
  }

  await recordAudit({ action: 'auth.login.success' }, supabase)

  // A password is only the first factor; where to go next depends on MFA state.
  const { data: aal } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel()
  if (aal?.currentLevel === 'aal2') redirect(DASHBOARD_PATH)
  redirect(aal?.nextLevel === 'aal2' ? MFA_VERIFY_PATH : MFA_ENROLL_PATH)
}
