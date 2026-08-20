'use server'

import { redirect } from 'next/navigation'

import { assertCsrf } from '@/lib/security/csrf'
import { NotAuthorisedError, requireSignedInUserOrThrow } from '@/lib/security/session'
import { recordAudit, recordAuditOrThrow } from '@/lib/audit'
import { DASHBOARD_PATH, MFA_ENROLL_PATH } from '@/lib/security/routes'

const SIX_DIGITS = /^\d{6}$/

export async function confirmEnrollmentAction(formData: FormData): Promise<void> {
  await assertCsrf(formData)
  // The proxy cannot cover this POST reliably, so the session is re-established here.
  const { supabase, user } = await requireSignedInUserOrThrow()

  // Refuse anyone who already holds a verified factor. They must answer THAT
  // challenge, not enrol a second one -- otherwise a stolen password alone is
  // enough to add an attacker-controlled factor and reach aal2. The enrol page
  // redirects such a user away; without this the action did not.
  if ((user.factors ?? []).some((factor) => factor.status === 'verified')) {
    throw new NotAuthorisedError('needs-verification')
  }

  const factorId = String(formData.get('factorId') ?? '')
  const code = String(formData.get('code') ?? '').trim()
  if (!SIX_DIGITS.test(code)) redirect(`${MFA_ENROLL_PATH}?error=code_format`)

  // The factor id came from a form field, so confirm it is one of this user's own.
  // Only unverified factors may be confirmed here, and only the user's own.
  const { data: factors, error: listError } = await supabase.auth.mfa.listFactors()
  if (listError || !factors?.all.some((factor) => factor.id === factorId && factor.status !== 'verified')) {
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
    await recordAuditOrThrow({
      action: 'auth.mfa.enroll.failure',
      targetType: 'mfa_factor',
      targetId: factorId,
      metadata: { reason: verifyError.message },
      actorUserId: user.id,
    })
    redirect(`${MFA_ENROLL_PATH}?error=invalid_code`)
  }

  await recordAuditOrThrow({
    action: 'auth.mfa.enroll',
    targetType: 'mfa_factor',
    targetId: factorId,
    actorUserId: user.id,
  })

  redirect(DASHBOARD_PATH)
}

/**
 * Discards a pending enrolment so the page can issue a fresh QR code.
 *
 * This exists because rendering the enrol page must not mutate anything. It is a
 * POST, so it carries a CSRF token, and it refuses a user who already holds a
 * verified factor for the same reason confirmEnrollmentAction does.
 */
export async function restartEnrollmentAction(formData: FormData): Promise<void> {
  await assertCsrf(formData)
  const { supabase, user } = await requireSignedInUserOrThrow()

  if ((user.factors ?? []).some((factor) => factor.status === 'verified')) {
    throw new NotAuthorisedError('needs-verification')
  }

  const { data: factors } = await supabase.auth.mfa.listFactors()
  for (const factor of factors?.all ?? []) {
    if (factor.factor_type === 'totp' && factor.status === 'unverified') {
      await supabase.auth.mfa.unenroll({ factorId: factor.id })
      await recordAudit({
        action: 'auth.mfa.enroll.restart',
        targetType: 'mfa_factor',
        targetId: factor.id,
        actorUserId: user.id,
      })
    }
  }

  redirect(MFA_ENROLL_PATH)
}
