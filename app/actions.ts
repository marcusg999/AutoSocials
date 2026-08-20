'use server'

import { cookies } from 'next/headers'
import { redirect } from 'next/navigation'

import { assertCsrf, clearCsrfToken } from '@/lib/security/csrf'
import { requireSignedInUserOrThrow } from '@/lib/security/session'
import { recordAuditOrThrow } from '@/lib/audit'
import { ACTIVE_BUSINESS_COOKIE } from '@/lib/business'
import { LOGIN_PATH } from '@/lib/security/routes'

/**
 * Signing out is allowed at aal1, otherwise a user who cannot complete MFA would
 * be stuck on the challenge screen forever.
 */
export async function signOutAction(formData: FormData): Promise<void> {
  await assertCsrf(formData)
  const { supabase, user } = await requireSignedInUserOrThrow()

  // Recorded before the session is destroyed, using the user id we just verified.
  await recordAuditOrThrow({ action: 'auth.signout', actorUserId: user.id })

  await supabase.auth.signOut()

  const cookieStore = await cookies()
  cookieStore.delete(ACTIVE_BUSINESS_COOKIE)
  await clearCsrfToken()

  redirect(LOGIN_PATH)
}
