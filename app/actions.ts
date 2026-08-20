'use server'

import { cookies } from 'next/headers'
import { redirect } from 'next/navigation'

import { assertCsrf } from '@/lib/security/csrf'
import { requireSignedInUserOrThrow } from '@/lib/security/session'
import { recordAudit } from '@/lib/audit'
import { ACTIVE_BUSINESS_COOKIE } from '@/lib/business'
import { LOGIN_PATH } from '@/lib/security/routes'

/**
 * Signing out is allowed at aal1, otherwise a user who cannot complete MFA would
 * be stuck on the challenge screen forever.
 */
export async function signOutAction(formData: FormData): Promise<void> {
  await assertCsrf(formData)
  const { supabase } = await requireSignedInUserOrThrow()

  // Recorded before the session is destroyed, because app.write_audit stamps the
  // actor from the JWT and there will not be one a moment from now.
  await recordAudit({ action: 'auth.signout' })

  await supabase.auth.signOut()

  const cookieStore = await cookies()
  cookieStore.delete(ACTIVE_BUSINESS_COOKIE)

  redirect(LOGIN_PATH)
}
