'use server'

import { redirect } from 'next/navigation'

import { assertCsrf } from '@/lib/security/csrf'
import { requireSignedInUserOrThrow } from '@/lib/security/session'
import { recordAudit } from '@/lib/audit'
import { DASHBOARD_PATH, MFA_VERIFY_PATH } from '@/lib/security/routes'

const SIX_DIGITS = /^\d{6}$/

export async function verifyFactorAction(formData: FormData): Promise<void> {
  await assertCsrf(formData)
  const { supabase } = await requireSignedInUserOrThrow()

  const factorId = String(formData.get('factorId') ?? '')
  const code = String(formData.get('code') ?? '').trim()
  if (!SIX_DIGITS.test(code)) redirect(`${MFA_VERIFY_PATH}?error=code_format`)

  // listFactors() returns only verified factors under `totp`, so this both proves
  // ownership and proves the factor is one that may be challenged.
  const { data: factors, error: listError } = await supabase.auth.mfa.listFactors()
  if (listError || !factors?.totp.some((factor) => factor.id === factorId)) {
    redirect(`${MFA_VERIFY_PATH}?error=unknown_factor`)
  }

  // The challenge is created here rather than on page render so it can never be stale.
  const { data: challenge, error: challengeError } = await supabase.auth.mfa.challenge({ factorId })
  if (challengeError || !challenge) redirect(`${MFA_VERIFY_PATH}?error=challenge_failed`)

  const { error: verifyError } = await supabase.auth.mfa.verify({
    factorId,
    challengeId: challenge.id,
    code,
  })

  if (verifyError) {
    await recordAudit({
      action: 'auth.mfa.verify.failure',
      targetType: 'mfa_factor',
      targetId: factorId,
      metadata: { reason: verifyError.message },
    })
    redirect(`${MFA_VERIFY_PATH}?error=invalid_code`)
  }

  await recordAudit({
    action: 'auth.mfa.verify',
    targetType: 'mfa_factor',
    targetId: factorId,
  })

  redirect(DASHBOARD_PATH)
}
