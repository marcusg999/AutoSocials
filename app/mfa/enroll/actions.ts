'use server'

import { redirect } from 'next/navigation'

import { assertCsrf } from '@/lib/security/csrf'
import { requireSignedInUserOrThrow } from '@/lib/security/session'
import { recordAudit } from '@/lib/audit'
import { DASHBOARD_PATH, MFA_ENROLL_PATH } from '@/lib/security/routes'

const SIX_DIGITS = /^\d{6}$/

export async function confirmEnrollmentAction(formData: FormData): Promise<void> {
  await assertCsrf(formData)
  // The proxy cannot cover this POST reliably, so the session is re-established here.
  const { supabase, user } = await requireSignedInUserOrThrow()

  const factorId = String(formData.get('factorId') ?? '')
  const code = String(formData.get('code') ?? '').trim()
  if (!SIX_DIGITS.test(code)) redirect(`${MFA_ENROLL_PATH}?error=code_format`)

  // The factor id came from a form field, so confirm it is one of this user's own.
  const { data: factors, error: listError } = await supabase.auth.mfa.listFactors()
  if (listError || !factors?.all.some((factor) => factor.id === factorId)) {
    redirect(`${MFA_ENROLL_PATH}?error=unknown_factor`)
  }

  const { data: challenge, error: challengeError } = await supabase.auth.mfa.challenge({ factorId })
  if (challengeError || !challenge) redirect(`${MFA_ENROLL_PATH}?error=challenge_failed`)

  const { error: verifyError } = await supabase.auth.mfa.verify({
    factorId,
    challengeId: challenge.id,
    code,
  })

  if (verifyError) {
    await recordAudit({
      action: 'auth.mfa.enroll.failure',
      targetType: 'mfa_factor',
      targetId: factorId,
      metadata: { reason: verifyError.message },
      actorUserId: user.id,
    })
    redirect(`${MFA_ENROLL_PATH}?error=invalid_code`)
  }

  await recordAudit({
    action: 'auth.mfa.enroll',
    targetType: 'mfa_factor',
    targetId: factorId,
    actorUserId: user.id,
  })

  redirect(DASHBOARD_PATH)
}
